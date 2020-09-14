package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicyVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.V36Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.V36CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.BaseConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.V36Config;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigBase;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigV36Custom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.V36ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildEnv;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildInfo;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote.RemoteFileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.remote.RemoteSastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import hudson.*;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.AbstractBuild;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import java.io.*;
import java.nio.charset.StandardCharsets;
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
        listener.getLogger().println(consolePrefix + String.format(format, args));
    }

    protected void log(TaskListener listener, String data) {
        listener.getLogger().println(consolePrefix + data);
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
        // Get all descriptors that may be used by plugin:
        // "UI-defined" scan settings descriptor
        ScanSettingsUi.Descriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class);
        // "JSON-defined" scan settings descriptor
        ScanSettingsManual.Descriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.Descriptor.class);
        // "PT AI EE server connection settings are defined globally" descriptor
        ConfigGlobal.Descriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.Descriptor.class);
        // "PT AI EE server connection settings are defined locally" descriptor
        ConfigV36Custom.Descriptor configV36CustomDescriptor = Jenkins.get().getDescriptorByType(ConfigV36Custom.Descriptor.class);

        boolean selectedScanSettingsUi = scanSettings instanceof ScanSettingsUi;
        String selectedScanSettings = selectedScanSettingsUi
                ? scanSettingsUiDescriptor.getDisplayName()
                : scanSettingsManualDescriptor.getDisplayName();

        String selectedConfig = config instanceof ConfigV36Custom
                ? configV36CustomDescriptor.getDisplayName()
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
            check = scanSettingsManualDescriptor.doTestJsonPolicy(item, jsonPolicy);
            if (FormValidation.Kind.OK != check.kind)
                throw new AbortException(check.getMessage());
            ScanSettings scanSettings = JsonSettingsVerifier.verify(jsonSettings);
            projectName = scanSettings.getProjectName();
            String changedProjectName = Util.replaceMacro(projectName, buildInfo.getEnvVars());
            if (!projectName.equals(changedProjectName))
                scanSettings.setProjectName(projectName);
            // These lines also minimize settings and policy JSONs
            jsonSettings = JsonSettingsVerifier.serialize(scanSettings);
            jsonPolicy = JsonPolicyVerifier.minimize(jsonPolicy);
        }

        V36ServerSettings serverSettings;
        String configName = null;
        V36Credentials credentials;
        String credentialsId;
        String serverUrl = null;

        if (configGlobalDescriptor.getDisplayName().equals(selectedConfig)) {
            // Settings are defined globally, job just refers them using configName
            configName = ((ConfigGlobal)config).getConfigName();
            BaseConfig base = descriptor.getConfig(configName);
            serverSettings = ((V36Config) base).getServerSettings();
            credentialsId = serverSettings.getServerCredentialsId();
            credentials = V36CredentialsImpl.getCredentialsById(item, credentialsId);
            serverUrl = serverSettings.getServerUrl();
        } else {
            ConfigV36Custom configV36Custom = (ConfigV36Custom) config;
            credentialsId = configV36Custom.getServerSettings().getServerCredentialsId();
            credentials = V36CredentialsImpl.getCredentialsById(item, credentialsId);
            serverUrl = configV36Custom.getServerSettings().getServerUrl();
        }

        check = descriptor.doTestProjectFields(
                selectedScanSettings,
                selectedConfig,
                jsonSettings, jsonPolicy,
                projectName,
                serverUrl, credentialsId, configName);
        if (FormValidation.Kind.OK != check.kind)
            throw new AbortException(check.getMessage());
        String node = StringUtils.isEmpty(nodeName) ? Base.DEFAULT_PTAI_NODE_NAME : nodeName;
        if (StringUtils.isEmpty(nodeName))
            verboseLog(listener, Messages.plugin_logDefaultNodeUsed(node));

        Project project = new Project(projectName);
        project.setConsole(listener.getLogger());
        project.setVerbose(this.verbose);
        project.setPrefix(this.consolePrefix);
        try {
            UUID scanResultId = null;
            try {
                project.setUrl(serverUrl);
                project.setToken(credentials.getPassword().getPlainText());
                if (StringUtils.isNotEmpty(credentials.getServerCaCertificates()))
                    project.setCaCertsPem(credentials.getServerCaCertificates());
                project.init();

                UUID projectId = project.searchProject();
                if (null == projectId) {
                    if (!selectedScanSettingsUi) {
                        project.out("Project %s not found, will be created as JSON settings are defined", projectName);
                        // TODO: implement project creation login
                        // project.getSastApi().createProject(projectName);
                    } else {
                        project.out("Project %s not found", projectName);
                        throw new AbortException(Messages.validator_test_ptaiProject_notfound());
                    }
                }

                File zip = zipSources(buildInfo, workspace, launcher, listener);
                project.setSources(zip);
                project.upload();

                scanResultId = project.scan(node);
                project.out("PT AI AST result ID is " + scanResultId);

                Stage stage = null;
                ScanProgress previousProgress = null;
                ScanResultStatistic previousStatistic = null;

                do {
                    Thread.sleep(5000);
                    ScanResult state = project.poll(projectId, scanResultId);
                    ScanProgress progress = state.getProgress();
                    ScanResultStatistic statistic = state.getStatistic();
                    if (null != progress || !progress.equals(previousProgress)) {
                        String progressInfo = "AST stage: " + progress.getStage() + ", percentage: " + progress.getValue();
                        project.out(progressInfo);
                        previousProgress = progress;
                    }
                    if (null != statistic || !statistic.equals(previousStatistic)) {
                        project.out("Scan duration: %s", statistic.getScanDuration());
                        if (0 != statistic.getTotalFileCount())
                            project.out("Scanned files: %d out of %d", statistic.getScannedFileCount(), statistic.getTotalFileCount());
                        previousStatistic = statistic;
                    }
                    if (null != progress) stage = progress.getStage();
                } while (!Stage.DONE.equals(stage) && !Stage.ABORTED.equals(stage) && !Stage.FAILED.equals(stage));

                RemoteSastJob sastJob = new RemoteSastJob(launcher);
                File json = project.getJsonResult(projectId, scanResultId);
                sastJob.saveReport(workspace.getRemote(), "report.json", FileUtils.readFileToString(json, StandardCharsets.UTF_8));

                if (failIfFailed && PolicyState.REJECTED.equals(previousStatistic.getPolicyState()))
                    throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastFailed());
                // TODO: Implement processing logic for unstable scans
                // if (failIfUnstable && JobState.StatusEnum.UNSTABLE.equals(state.getStatus()))
                //     throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastUnstable());
            } catch (InterruptedException e) {
                if ((null != project) && (null != scanResultId)) project.stop(scanResultId);
                throw e;
            }
        } catch (ApiException e) {
            project.out(Messages.validator_failedPtaiApiDetails(e.getMessage()), e);
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