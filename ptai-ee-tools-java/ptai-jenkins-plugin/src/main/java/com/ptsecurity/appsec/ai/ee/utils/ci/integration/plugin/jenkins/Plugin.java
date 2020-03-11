package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.CredentialsAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.TokenAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.BaseConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.LegacyConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.SlimConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigBase;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigLegacyCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigSlimCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.SlimServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildEnv;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildInfo;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote.RemoteFileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote.RemoteSastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
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
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;

import static org.apache.commons.lang3.StringUtils.trimToNull;

@Slf4j
@ToString
public class Plugin extends Builder implements SimpleBuildStep {
    public static final String CLIENT_ID = "ptai-jenkins-plugin";
    public static final String CLIENT_SECRET = "etg76M18UsOGMPLRliwCn2r3g8BlO7TZ";

    private static final String consolePrefix = com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.console_message_prefix();

    @Getter
    private final ConfigBase config;

    @Getter
    private final com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings scanSettings;

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
    public Plugin(final com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings scanSettings,
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

    protected File zipSources(BuildInfo buildInfo, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
        // Zip sources
        Transfers transfers = new Transfers();
        for (Transfer transfer : this.transfers)
            transfers.addTransfer(com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer.builder()
                    .excludes(Util.replaceMacro(transfer.getExcludes(), buildInfo.getEnvVars()))
                    .flatten(transfer.isFlatten())
                    .useDefaultExcludes(transfer.isUseDefaultExcludes())
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
        return zipFile;
    }

    @Override
    public void perform(@Nonnull Run<?, ?> build, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener) throws IOException, InterruptedException {
        Jenkins jenkins = Jenkins.get();
        final BuildEnv currentBuildEnv = new BuildEnv(getEnvironmentVariables(build, listener), workspace, build.getTimestamp());
        final BuildEnv targetBuildEnv = null;
        final BuildInfo buildInfo = new BuildInfo(currentBuildEnv, targetBuildEnv);
        buildInfo.setEffectiveEnvironmentInBuildInfo();

        Item item = jenkins.getItem("/");
        if (build instanceof AbstractBuild)
            item = ((AbstractBuild)build).getProject();

        PluginDescriptor descriptor = this.getDescriptor();

        FormValidation check = null;

        ScanSettingsUi.Descriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class);
        ScanSettingsManual.Descriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.Descriptor.class);
        ConfigGlobal.Descriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.Descriptor.class);
        ConfigLegacyCustom.Descriptor configLegacyCustomDescriptor = Jenkins.get().getDescriptorByType(ConfigLegacyCustom.Descriptor.class);
        ConfigSlimCustom.Descriptor configSlimCustomDescriptor = Jenkins.get().getDescriptorByType(ConfigSlimCustom.Descriptor.class);

        String selectedScanSettings = scanSettings instanceof ScanSettingsManual
                ? scanSettingsManualDescriptor.getDisplayName()
                : scanSettingsUiDescriptor.getDisplayName();
        boolean selectedScanSettingsUi = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class).getDisplayName().equals(selectedScanSettings);

        String selectedConfig = config instanceof ConfigLegacyCustom
                ? configLegacyCustomDescriptor.getDisplayName()
                : config instanceof ConfigSlimCustom
                ? configSlimCustomDescriptor.getDisplayName()
                : configGlobalDescriptor.getDisplayName();

        String jsonSettings = selectedScanSettingsUi ? null : ((ScanSettingsManual) scanSettings).getJsonSettings();
        String jsonPolicy = selectedScanSettingsUi ? null : ((ScanSettingsManual) scanSettings).getJsonPolicy();

        String projectName = null;
        if (selectedScanSettingsUi) {
            projectName = ((ScanSettingsUi) scanSettings).getProjectName();
            projectName = Util.replaceMacro(projectName, buildInfo.getEnvVars());
        } else {
            check = scanSettingsManualDescriptor.doTestJsonSettings(item, jsonSettings);
            if (FormValidation.Kind.OK != check.kind)
                throw new AbortException(check.getMessage());
            ScanSettings scanSettings = JsonSettingsVerifier.verify(jsonSettings);
            projectName = scanSettings.getProjectName();
            String changedProjectName = Util.replaceMacro(projectName, buildInfo.getEnvVars());
            if (!projectName.equals(changedProjectName)) {
                scanSettings.setProjectName(projectName);
                jsonSettings = JsonSettingsVerifier.serialize(scanSettings);
            }
        }

        LegacyServerSettings legacyServerSettings = null;
        SlimServerSettings slimServerSettings = null;
        String configName = null;
        LegacyCredentials legacyCredentials = null;
        String legacyCredentialsId = null;
        SlimCredentials slimCredentials = null;
        String slimCredentialsId = null;
        String serverUrl = null;
        String jenkinsServerUrl = null;
        String jenkinsJobName = null;
        Auth jenkinsServerCredentials = null;

        if (configGlobalDescriptor.getDisplayName().equals(selectedConfig)) {
            // Settings are defined globally, job just refers them using configName
            configName = ((ConfigGlobal)config).getConfigName();
            BaseConfig base = descriptor.getConfig(configName);
            // What is the type of global config?
            if (base instanceof LegacyConfig) {
                legacyServerSettings = ((LegacyConfig) base).getLegacyServerSettings();
                legacyCredentialsId = legacyServerSettings.getServerLegacyCredentialsId();
                legacyCredentials = LegacyCredentialsImpl.getCredentialsById(item, legacyCredentialsId);
                serverUrl = legacyServerSettings.getServerLegacyUrl();
                jenkinsServerUrl = legacyServerSettings.getJenkinsServerUrl();
                jenkinsJobName = legacyServerSettings.getJenkinsServerUrl();
                jenkinsServerCredentials = legacyServerSettings.getJenkinsServerCredentials();
            } else {
                slimServerSettings = ((SlimConfig) base).getSlimServerSettings();
                slimCredentialsId = slimServerSettings.getServerSlimCredentialsId();
                slimCredentials = SlimCredentialsImpl.getCredentialsById(item, slimCredentialsId);
                serverUrl = slimServerSettings.getServerSlimUrl();
            }
        } else if (configLegacyCustomDescriptor.getDisplayName().equals(selectedConfig)) {
            ConfigLegacyCustom configLegacyCustom = (ConfigLegacyCustom) config;
            legacyServerSettings = configLegacyCustom.getLegacyServerSettings();
            legacyCredentialsId = configLegacyCustom.getLegacyServerSettings().getServerLegacyCredentialsId();
            legacyCredentials = LegacyCredentialsImpl.getCredentialsById(item, legacyCredentialsId);
            serverUrl = configLegacyCustom.getLegacyServerSettings().getServerLegacyUrl();
            jenkinsServerUrl = legacyServerSettings.getJenkinsServerUrl();
            jenkinsJobName = legacyServerSettings.getJenkinsServerUrl();
            jenkinsServerCredentials = legacyServerSettings.getJenkinsServerCredentials();
        } else {
            ConfigSlimCustom configSlimCustom = (ConfigSlimCustom) config;
            slimCredentialsId = configSlimCustom.getSlimServerSettings().getServerSlimCredentialsId();
            slimCredentials = SlimCredentialsImpl.getCredentialsById(item, slimCredentialsId);
            serverUrl = configSlimCustom.getSlimServerSettings().getServerSlimUrl();
        }

        check = descriptor.doTestProjectFields(
                selectedScanSettings,
                selectedConfig,
                jsonSettings, jsonPolicy,
                projectName,
                serverUrl, legacyCredentialsId, jenkinsServerUrl, jenkinsJobName, serverUrl, slimCredentialsId, configName);
        if (FormValidation.Kind.OK != check.kind)
            throw new AbortException(check.getMessage());
        try {
            PtaiProject ptaiProject = null;
            Client client = null;
            if (null != legacyServerSettings) {
                // Legacy mode
                ptaiProject = new PtaiProject();
                ptaiProject.setName(projectName);
                ptaiProject.setVerbose(this.verbose);
                ptaiProject.setConsoleLog(listener.getLogger());
                ptaiProject.setLogPrefix(this.consolePrefix);
                ptaiProject.setUrl(legacyServerSettings.getServerLegacyUrl());
                ptaiProject.setKeyPem(legacyCredentials.getClientCertificate());
                ptaiProject.setKeyPassword(legacyCredentials.getClientKey().getPlainText());
                ptaiProject.setCaCertsPem(legacyCredentials.getServerCaCertificates());
                // Try to authenticate
                String ptaiToken = ptaiProject.init();
                if (StringUtils.isEmpty(ptaiToken))
                    throw new AbortException(Messages.validator_test_server_token_invalid());
                verboseLog(listener, Messages.validator_test_server_success(ptaiToken.substring(0, 10)) + "\r\n");

                UUID projectId = ptaiProject.searchProject();
                if (null == projectId) {
                    if (!selectedScanSettingsUi)
                        projectId = ptaiProject.createProject(projectName);
                    else
                        throw new AbortException(Messages.validator_test_ptaiProject_notfound());
                }
                verboseLog(listener, Messages.validator_test_ptaiProject_success(projectId.toString().substring(0, 4)) + "\r\n");
                File zipFile = this.zipSources(buildInfo, workspace, launcher, listener);
                ptaiProject.upload(zipFile);

                // Let's start analysis
                RemoteSastJob sastJob = new RemoteSastJob(launcher);
                sastJob.setVerbose(verbose);
                sastJob.setConsoleLog(listener.getLogger());
                sastJob.setLogPrefix(this.consolePrefix);
                sastJob.setUrl(legacyServerSettings.getJenkinsServerUrl());
                sastJob.setJobName(legacyServerSettings.getJenkinsJobName());
                sastJob.setCaCertsPem(legacyCredentials.getServerCaCertificates());
                sastJob.setProjectName(ptaiProject.getName());
                sastJob.setJenkinsMaxRetry(legacyServerSettings.getJenkinsMaxRetry());
                sastJob.setJenkinsRetryDelay(legacyServerSettings.getJenkinsRetryDelay());
                if (scanSettings instanceof ScanSettingsManual) {
                    sastJob.setSettingsJson(jsonSettings);
                    sastJob.setPolicyJson(jsonPolicy);
                }
                sastJob.setNodeName(this.nodeName);
                // Set authentication parameters
                if (null == jenkinsServerCredentials)
                    throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedJenkinsAuthNotSet());
                if (jenkinsServerCredentials instanceof CredentialsAuth) {
                    CredentialsAuth auth = (CredentialsAuth)jenkinsServerCredentials;
                    sastJob.setUserName(auth.getUserName(item));
                    sastJob.setPassword(auth.getPassword(item));
                } else if (jenkinsServerCredentials instanceof TokenAuth) {
                    // Jenkins API token authentication is not the same as JWT (i.e. "bearer" one)
                    // It is just another form of login/password authentication
                    TokenAuth auth = (TokenAuth)jenkinsServerCredentials;
                    sastJob.setUserName(auth.getUserName());
                    sastJob.setPassword(auth.getApiToken());
                }
                sastJob.init();
                PtaiResultStatus sastJobRes = sastJob.execute(workspace.getRemote());

                if (failIfFailed && PtaiResultStatus.FAILURE.equals(sastJobRes))
                    throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastFailed());
                if (failIfUnstable && PtaiResultStatus.UNSTABLE.equals(sastJobRes))
                    throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastUnstable());
            } else {
                // Slim mode
                Integer scanId = null;
                try {
                    client = new Client();
                    client.setConsoleLog(listener.getLogger());
                    client.setVerbose(this.verbose);
                    client.setLogPrefix(this.consolePrefix);

                    client.setUrl(serverUrl);
                    client.setClientId(Plugin.CLIENT_ID);
                    client.setClientSecret(Plugin.CLIENT_SECRET);
                    client.setUserName(slimCredentials.getUserName());
                    client.setPassword(slimCredentials.getPassword().getPlainText());
                    if (!org.apache.commons.lang.StringUtils.isEmpty(slimCredentials.getServerCaCertificates()))
                        client.setCaCertsPem(slimCredentials.getServerCaCertificates());
                    client.init();

                    File zipFile = this.zipSources(buildInfo, workspace, launcher, listener);
                    client.uploadZip(projectName, zipFile, 1024 * 1024);
                    scanId = client.getSastApi().startUiJob(projectName, this.nodeName);
                    log(listener, "SAST job number is " + scanId);

                    JobState state = null;
                    int pos = 0;
                    do {
                        state = client.getSastApi().getScanJobState(scanId, pos);
                        if (state.getPos() != pos) {
                            String[] lines = state.getLog().split("\\r?\\n");
                            for (String line : lines)
                                log(listener, "%s\r\n", line);
                        }
                        pos = state.getPos();
                        if (!state.getStatus().equals(JobState.StatusEnum.UNKNOWN)) break;
                        Thread.sleep(2000);
                    } while (true);

                    RemoteSastJob sastJob = new RemoteSastJob(launcher);
                    List<String> results = client.getSastApi().getJobResults(scanId);
                    for (String result : results) {
                        File data = client.getSastApi().getJobResult(scanId, result);
                        String fileName = result.replaceAll("REPORTS", Base.SAST_FOLDER);
                        sastJob.saveReport(workspace.getRemote(), fileName, FileUtils.readFileToString(data, StandardCharsets.UTF_8));
                    }
                    if (failIfFailed && JobState.StatusEnum.FAILURE.equals(state.getStatus()))
                        throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastFailed());
                    if (failIfUnstable && JobState.StatusEnum.UNSTABLE.equals(state.getStatus()))
                        throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastUnstable());
                } catch (InterruptedException e) {
                    if ((null != client) && (null != scanId))
                        client.getSastApi().stopScan(scanId);
                    throw e;
                }
            }
        } catch (JenkinsClientException e) {
            log(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedJenkinsApiDetails(e) + "\r\n");
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failed());
        } catch (PtaiClientException e) {
            log(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedPtaiApiDetails(e) + "\r\n");
            throw new AbortException(Messages.validator_failed());
        } catch (ApiException e) {
            log(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedPtaiApiDetails(new BaseClientException(null, e)) + "\r\n");
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