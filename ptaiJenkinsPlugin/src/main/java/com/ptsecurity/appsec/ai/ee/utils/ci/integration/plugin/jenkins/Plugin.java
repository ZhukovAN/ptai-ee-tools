package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.CredentialsAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.TokenAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config.ConfigBase;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config.ConfigCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildEnv;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildInfo;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote.RemoteFileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote.RemoteSastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import hudson.AbortException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.*;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import java.io.*;
import java.util.*;

import static org.apache.commons.lang3.StringUtils.trimToNull;

@Slf4j
@ToString
public class Plugin extends Builder implements SimpleBuildStep {
    private static final String consolePrefix = com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.console_message_prefix();

    @Getter
    private final ConfigBase config;

    @Getter
    private final ScanSettings scanSettings;

    @Getter
    private final boolean failIfFailed;

    @Getter
    private final boolean failIfUnstable;

    @Getter
    private final String nodeName;

    @Getter
    private final boolean verbose;

    @Getter
    private ArrayList<Transfer> transfers;

    public final void setTransfers(final ArrayList<Transfer> transfers) {
        if (transfers == null)
            this.transfers = new ArrayList<>();
        else
            this.transfers = transfers;
    }

    @DataBoundConstructor
    public Plugin(final ScanSettings scanSettings,
                  final ConfigBase config,
                  final boolean failIfFailed,
                  final boolean failIfUnstable,
                  final String nodeName,
                  final boolean verbose,
                  final ArrayList<Transfer> transfers) {
        this.scanSettings = scanSettings;
        this.config = config;
        this.failIfFailed = failIfFailed;
        this.failIfUnstable = failIfUnstable;
        this.verbose = verbose;
        this.nodeName = nodeName;
        this.transfers = transfers;
    }

    private TreeMap<String, String> getEnvironmentVariables(final Run<?, ?> build, final TaskListener listener) {
        try {
            final TreeMap<String, String> env = build.getEnvironment(listener);
            if (build instanceof AbstractBuild) {
                env.putAll(((AbstractBuild) build).getBuildVariables());
            }
            return env;
        } catch (Exception e) {
            throw new RuntimeException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.exception_failedToGetEnvVars(), e);
        }
    }

    protected void verboseLog(TaskListener listener, String format, Object... args) {
        if (!this.verbose) return;
        log(listener, format, args);
    }

    protected void log(TaskListener listener, String format, Object... args) {
        listener.getLogger().print(consolePrefix + String.format(format, args));
    }

    @Override
    public void perform(@Nonnull Run<?, ?> build, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener) throws InterruptedException, IOException {
        Jenkins jenkins = Jenkins.get();
        final BuildEnv currentBuildEnv = new BuildEnv(getEnvironmentVariables(build, listener), workspace, build.getTimestamp());
        final BuildEnv targetBuildEnv = null;
        final BuildInfo buildInfo = new BuildInfo(currentBuildEnv, targetBuildEnv);
        buildInfo.setEffectiveEnvironmentInBuildInfo();

        PluginDescriptor descriptor = this.getDescriptor();
        FormValidation check = descriptor.doTestProjectFields(
                // selectedScanSettings
                scanSettings instanceof ScanSettingsManual
                        ? jenkins.getDescriptorByType(ScanSettingsManual.ScanSettingsManualDescriptor.class).getDisplayName()
                        : jenkins.getDescriptorByType(ScanSettingsUi.ScanSettingsUiDescriptor.class).getDisplayName(),
                // selectedConfig
                config instanceof ConfigCustom
                        ? jenkins.getDescriptorByType(ConfigCustom.ConfigCustomDescriptor.class).getDisplayName()
                        : jenkins.getDescriptorByType(ConfigGlobal.ConfigGlobalDescriptor.class).getDisplayName(),
                // jsonSettings
                scanSettings instanceof ScanSettingsManual
                        ? ((ScanSettingsManual)scanSettings).getJsonSettings()
                        : "",
                // jsonPolicy
                scanSettings instanceof ScanSettingsManual
                        ? ((ScanSettingsManual)scanSettings).getJsonPolicy()
                        : "",
                // projectName
                scanSettings instanceof ScanSettingsManual
                        ? ""
                        : ((ScanSettingsUi)scanSettings).getProjectName(),
                // serverUrl
                this.config instanceof ConfigCustom
                        ? ((ConfigCustom)config).getServerSettings().getServerUrl()
                        : descriptor.getConfig(((ConfigGlobal)config).getConfigName()).getServerSettings().getServerUrl(),
                // serverCredentialsId
                this.config instanceof ConfigCustom
                        ? ((ConfigCustom)config).getServerSettings().getServerCredentialsId()
                        : descriptor.getConfig(((ConfigGlobal)config).getConfigName()).getServerSettings().getServerCredentialsId(),
                // jenkinsServerUrl
                this.config instanceof ConfigCustom
                        ? ((ConfigCustom)config).getServerSettings().getJenkinsServerUrl()
                        : descriptor.getConfig(((ConfigGlobal)config).getConfigName()).getServerSettings().getJenkinsServerUrl(),
                // jenkinsJobName
                this.config instanceof ConfigCustom
                        ? ((ConfigCustom)config).getServerSettings().getJenkinsJobName()
                        : descriptor.getConfig(((ConfigGlobal)config).getConfigName()).getServerSettings().getJenkinsJobName(),
                // configName
                config instanceof ConfigCustom
                        ? ""
                        : ((ConfigGlobal)config).getConfigName());
        if (FormValidation.Kind.OK != check.kind)
            throw new AbortException(check.getMessage());

        ServerSettings settings = this.config instanceof ConfigCustom
                ? ((ConfigCustom)config).getServerSettings()
                : descriptor.getConfig(((ConfigGlobal)config).getConfigName()).getServerSettings();

        Item item = jenkins.getItem("/");
        if (build instanceof AbstractBuild)
            item = ((AbstractBuild)build).getProject();

        ServerCredentials ptaiCreds = ServerCredentialsImpl.getCredentialsById(item, settings.getServerCredentialsId());
    /*
        if (StringUtils.isEmpty(ptaiCreds.getClientCertificate()))
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_emptyPtaiCert());
        if (StringUtils.isEmpty(ptaiCreds.getClientKey().getPlainText()))
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_emptyPtaiCertPwd());
        if (StringUtils.isEmpty(ptaiCreds.getServerCaCertificates()))
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_emptyPtaiCaCerts());
*/
        PtaiProject ptaiProject = new PtaiProject();
        ptaiProject.setVerbose(this.verbose);
        ptaiProject.setConsoleLog(listener.getLogger());
        ptaiProject.setLogPrefix(this.consolePrefix);
        ptaiProject.setUrl(settings.getServerUrl());
        ptaiProject.setKeyPem(ptaiCreds.getClientCertificate());
        ptaiProject.setKeyPassword(ptaiCreds.getClientKey().getPlainText());
        ptaiProject.setCaCertsPem(ptaiCreds.getServerCaCertificates());
        if (scanSettings instanceof ScanSettingsManual) {
            ptaiProject.setJsonSettings(((ScanSettingsManual) scanSettings).getJsonSettings());
            ptaiProject.setJsonPolicy(((ScanSettingsManual) scanSettings).getJsonPolicy());
        }

        // Connect to PT AI server
        try {
            // Try to authenticate
            String ptaiToken = ptaiProject.init();
            if (StringUtils.isEmpty(ptaiToken))
                throw new AbortException(Messages.validator_test_server_token_invalid());
            verboseLog(listener, Messages.validator_test_server_success(ptaiToken.substring(0, 10)) + "\r\n");

            // Search for project
            String uiPrj = Util.replaceMacro(
                    scanSettings instanceof ScanSettingsManual
                            ? JsonSettingsVerifier.verify(((ScanSettingsManual)scanSettings).getJsonSettings()).ProjectName
                            : ((ScanSettingsUi)scanSettings).getProjectName(),
                    buildInfo.getEnvVars());
            uiPrj = Util.fixEmptyAndTrim(uiPrj);
            ptaiProject.setName(uiPrj);

            UUID projectId = ptaiProject.searchProject();
            if (null == projectId) {
                if (scanSettings instanceof ScanSettingsManual) {
                    JsonSettings jsonSettings = JsonSettingsVerifier.verify(((ScanSettingsManual)scanSettings).getJsonSettings());
                    projectId = ptaiProject.createProject(jsonSettings);
                } else
                    throw new AbortException(Messages.validator_test_ptaiProject_notfound());
            }
            verboseLog(listener, Messages.validator_test_ptaiProject_success(projectId.toString().substring(0, 4)) + "\r\n");

            Transfers transfers = new Transfers();
            for (Transfer transfer : this.transfers)
                transfers.addTransfer(com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer.builder()
                        .excludes(Util.replaceMacro(transfer.getExcludes(), buildInfo.getEnvVars()))
                        .flatten(transfer.isFlatten())
                        .includes(Util.replaceMacro(transfer.getIncludes(), buildInfo.getEnvVars()))
                        .patternSeparator(transfer.getPatternSeparator())
                        .removePrefix(Util.replaceMacro(transfer.getRemovePrefix(), buildInfo.getEnvVars()))
                        .build());

            // Upload project sources
            FilePath remoteZip = new RemoteFileCollector().collect(launcher, listener, transfers, workspace.getRemote(), verbose);
            File zipFile = File.createTempFile("PTAI_", ".zip");
            try (OutputStream fos = new FileOutputStream(zipFile)) {
                remoteZip.copyTo(fos);
                remoteZip.delete();
            }
            ptaiProject.upload(zipFile);

            // Let's start analysis
            RemoteSastJob sastJob = new RemoteSastJob(launcher);
            sastJob.setVerbose(verbose);
            sastJob.setConsoleLog(listener.getLogger());
            sastJob.setLogPrefix(this.consolePrefix);
            sastJob.setUrl(settings.getJenkinsServerUrl());
            sastJob.setJobName(settings.getJenkinsJobName());
            sastJob.setCaCertsPem(ptaiCreds.getServerCaCertificates());
            sastJob.setProjectName(ptaiProject.getName());
            sastJob.setJenkinsMaxRetry(settings.getJenkinsMaxRetry());
            sastJob.setJenkinsRetryDelay(settings.getJenkinsRetryDelay());
            if (scanSettings instanceof ScanSettingsManual) {
                sastJob.setSettingsJson(((ScanSettingsManual)scanSettings).getJsonSettings());
                sastJob.setPolicyJson(((ScanSettingsManual)scanSettings).getJsonPolicy());
            }
            sastJob.setNodeName(this.nodeName);
            // Set authentication parameters
            Auth jenkinsAuth = settings.getJenkinsServerCredentials();
            if (null == jenkinsAuth)
                throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedJenkinsAuthNotSet());
            if (jenkinsAuth instanceof CredentialsAuth) {
                CredentialsAuth auth = (CredentialsAuth)jenkinsAuth;
                sastJob.setUserName(auth.getUserName(item));
                sastJob.setPassword(auth.getPassword(item));
            } else if (jenkinsAuth instanceof TokenAuth) {
                // Jenkins API token authentication is not the same as JWT (i.e. "bearer" one)
                // It is just another form of login/password authentication
                TokenAuth auth = (TokenAuth)jenkinsAuth;
                sastJob.setUserName(auth.getUserName());
                sastJob.setPassword(auth.getApiToken());
            }
            sastJob.init();
            PtaiResultStatus sastJobRes = sastJob.execute(workspace.getRemote());

            if (failIfFailed && PtaiResultStatus.FAILURE.equals(sastJobRes))
                throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastFailed());
            if (failIfUnstable && PtaiResultStatus.UNSTABLE.equals(sastJobRes))
                throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastUnstable());
        } catch (JenkinsClientException e) {
            log(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedJenkinsApiDetails(e) + "\r\n");
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failed());
        } catch (PtaiClientException e) {
            log(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedPtaiApiDetails(e) + "\r\n");
            throw new AbortException(Messages.validator_failed());
        }
    }

    @Override
    public PluginDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(PluginDescriptor.class);
    }

    protected static String getCurrentItem(Run<?, ?> run, String currentItem){
        String runItem = null;
        String curItem = trimToNull(currentItem);
        if(run != null && run.getParent() != null)
            runItem = trimToNull(run.getParent().getFullName());

        if(runItem != null && curItem != null) {
            if(runItem.equals(curItem)) {
                return runItem;
            } else {
                throw new IllegalArgumentException(String.format("Current Item ('%s') and Parent Item from Run ('%s') differ!", curItem, runItem));
            }
        } else if(runItem != null) {
            return runItem;
        } else if(curItem != null) {
            return curItem;
        } else {
            throw new IllegalArgumentException("Both null, Run and Current Item!");
        }
    }
}