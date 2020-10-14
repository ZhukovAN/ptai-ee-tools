package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.BaseConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.Config;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigBase;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.Report;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildEnv;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildInfo;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.RemoteFileUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkMode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeAsync;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ReportHelper;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import hudson.*;
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
import lombok.extern.java.Log;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.trimToNull;

@Log
@ToString
public class Plugin extends Builder implements SimpleBuildStep {
    private static final String CONSOLE_PREFIX = Base.DEFAULT_PREFIX;

    @Getter
    private final ConfigBase config;

    @Getter
    private final com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings scanSettings;

    @Getter
    private final String nodeName;

    @Getter
    private final WorkMode workMode;

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
                  final WorkMode workMode,
                  final String nodeName,
                  final boolean verbose,
                  final ArrayList<Transfer> transfers) {
        this.scanSettings = scanSettings;
        this.config = config;
        this.workMode = workMode;
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
            throw new RuntimeException(Messages.exception_failedToGetEnvVars(), e);
        }
    }

    private File zipSources(BuildInfo buildInfo, FilePath workspace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
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
        FilePath remoteZip = RemoteFileUtils.collect(launcher, listener, transfers, workspace.getRemote(), verbose);
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
        final BuildInfo buildInfo = new BuildInfo(currentBuildEnv, null);
        buildInfo.setEffectiveEnvironmentInBuildInfo();

        Item item = jenkins.getItem("/");
        if (build instanceof AbstractBuild)
            item = ((AbstractBuild)build).getProject();

        PluginDescriptor descriptor = this.getDescriptor();

        FormValidation check;
        // Get all descriptors that may be used by plugin:
        // "UI-defined" scan settings descriptor
        ScanSettingsUi.Descriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class);
        // "JSON-defined" scan settings descriptor
        ScanSettingsManual.Descriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.Descriptor.class);
        // "PT AI EE server connection settings are defined globally" descriptor
        ConfigGlobal.Descriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.Descriptor.class);
        // "PT AI EE server connection settings are defined locally" descriptor
        ConfigCustom.Descriptor configCustomDescriptor = Jenkins.get().getDescriptorByType(ConfigCustom.Descriptor.class);

        boolean failIfFailed = (workMode instanceof WorkModeSync) && ((WorkModeSync) workMode).isFailIfFailed();
        boolean failIfUnstable = (workMode instanceof WorkModeSync) && ((WorkModeSync) workMode).isFailIfUnstable();

        boolean selectedScanSettingsUi = scanSettings instanceof ScanSettingsUi;
        String selectedScanSettings = selectedScanSettingsUi
                ? scanSettingsUiDescriptor.getDisplayName()
                : scanSettingsManualDescriptor.getDisplayName();

        String selectedConfig = config instanceof ConfigCustom
                ? configCustomDescriptor.getDisplayName()
                : configGlobalDescriptor.getDisplayName();

        String jsonSettings = selectedScanSettingsUi ? null : ((ScanSettingsManual) scanSettings).getJsonSettings();
        String jsonPolicy = selectedScanSettingsUi ? null : ((ScanSettingsManual) scanSettings).getJsonPolicy();

        String projectName;
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
            ScanSettings scanSettings = JsonSettingsHelper.verify(jsonSettings);
            projectName = scanSettings.getProjectName();
            String changedProjectName = Util.replaceMacro(projectName, buildInfo.getEnvVars());
            if (!projectName.equals(changedProjectName))
                scanSettings.setProjectName(projectName);
            // These lines also minimize settings and policy JSONs
            jsonSettings = JsonSettingsHelper.serialize(scanSettings);
            if (StringUtils.isNotEmpty(jsonPolicy))
                jsonPolicy = JsonPolicyHelper.minimize(jsonPolicy);
        }

        ServerSettings serverSettings;
        String configName = null;
        Credentials credentials;
        String credentialsId;
        String serverUrl;

        if (config instanceof ConfigGlobal) {
            // Settings are defined globally, job just refers them using configName
            configName = ((ConfigGlobal)config).getConfigName();
            BaseConfig base = descriptor.getConfig(configName);
            serverSettings = ((Config) base).getServerSettings();
            credentialsId = serverSettings.getServerCredentialsId();
            credentials = CredentialsImpl.getCredentialsById(item, credentialsId);
            serverUrl = serverSettings.getServerUrl();
        } else {
            ConfigCustom configCustom = (ConfigCustom) config;
            credentialsId = configCustom.getServerSettings().getServerCredentialsId();
            credentials = CredentialsImpl.getCredentialsById(item, credentialsId);
            serverUrl = configCustom.getServerSettings().getServerUrl();
        }

        check = descriptor.doTestProjectFields(
                selectedScanSettings,
                selectedConfig,
                jsonSettings, jsonPolicy,
                projectName,
                serverUrl, credentialsId, configName);
        if (FormValidation.Kind.OK != check.kind)
            throw new AbortException(check.getMessage());
        // TODO: Implement scan node support when PT AI will be able to
        String node = StringUtils.isEmpty(nodeName) ? Base.DEFAULT_PTAI_NODE_NAME : nodeName;

        Project project = new Project(projectName);
        project.setConsole(listener.getLogger());
        project.setVerbose(verbose);
        project.setPrefix(CONSOLE_PREFIX);
        UUID scanResultId = null;

        try {
            project.setUrl(serverUrl);
            project.setToken(credentials.getToken().getPlainText());
            if (StringUtils.isNotEmpty(credentials.getServerCaCertificates()))
                project.setCaCertsPem(credentials.getServerCaCertificates());
            project.init();

            UUID projectId = project.searchProject();
            if (null == projectId) {
                if (!selectedScanSettingsUi) {
                    project.info("Project %s not found, will be created as JSON settings are defined", projectName);
                    projectId = project.setupFromJson(JsonSettingsHelper.verify(jsonSettings), JsonPolicyHelper.verify(jsonPolicy));
                } else {
                    project.info("Project %s not found", projectName);
                    throw new AbortException(Messages.validator_test_ptaiProject_notfound());
                }
            } else if (!selectedScanSettingsUi)
                project.setupFromJson(JsonSettingsHelper.verify(jsonSettings), JsonPolicyHelper.verify(jsonPolicy));

            File zip = zipSources(buildInfo, workspace, launcher, listener);
            project.setSources(zip);
            project.upload();

            scanResultId = project.scan(node);
            project.info("PT AI AST result ID is " + scanResultId);

            // Save scan result URL for future use
            String url = String.format("%s/api/Projects/%s/scanResults/%s", project.getUrl(), projectId, scanResultId);
            RemoteFileUtils.saveReport(launcher, listener, workspace.getRemote(), "result.url", url.getBytes(StandardCharsets.UTF_8), verbose);
            if (workMode instanceof WorkModeAsync) {
                // Asynchronous mode means that we aren't need to wait AST job
                // completion. Just write scan result access URL and exit
                return;
            }

            WorkModeSync workModeSync = (WorkModeSync) workMode;

            boolean failed = false;
            boolean unstable = false;
            String reason;

            ScanResult state = project.waitForComplete(scanResultId);
            Stage stage = state.getProgress().getStage();

            log.finer("Resulting stage is " + stage);
            log.finer("Resulting statistics is " + state.getStatistic());

            List<ScanError> scanErrors = project.getScanErrors(projectId, scanResultId);
            failed |=  scanErrors.stream().filter(ScanError::getIsCritical).findAny().isPresent();
            unstable |=  scanErrors.stream().filter(e -> !e.getIsCritical()).findAny().isPresent();

            if (Stage.DONE.equals(stage) || Stage.ABORTED.equals(stage)) {
                // Save reports if scan was started ever
                int idx = 0;
                // Generate unique report names as reports defined in job settings may have duplicates
                final String duplicateReportIndexPlaceholder = UUID.randomUUID().toString();
                Map<String, Long> counters = workModeSync.getReports().stream()
                        .collect(Collectors.groupingBy(r -> r.fileNameTemplate(), Collectors.counting()));
                Map<String, Long> duplicateIndexes = new HashMap<>();

                for (Report report : workModeSync.getReports()) {
                    String name = report.fileNameTemplate();
                    if (1 == counters.get(name))
                        name = ReportHelper.removePlaceholder(name);
                    else {
                        Long duplicateIndex = duplicateIndexes.getOrDefault(name, Long.valueOf(1));
                        String duplicateName = ReportHelper.replacePlaceholder(name, "." + duplicateIndex);
                        duplicateIndex++;
                        duplicateIndexes.put(name, duplicateIndex);
                        name = duplicateName;
                    }
                    try {
                        ReportFormatType type = ReportFormatType.fromValue(report.getFormat());
                        File reportFile = project.generateReport(projectId, scanResultId, report.getTemplate(), type, report.getLocale());
                        byte[] data = FileUtils.readFileToByteArray(reportFile);
                        RemoteFileUtils.saveReport(launcher, listener, workspace.getRemote(), name, data, verbose);
                        project.fine("Report saved as %s", name);
                    } catch (ApiException e) {
                        project.warning(Messages.plugin_result_ast_warning(e.getMessage()), e);
                        unstable = true;
                    }
                }
                File json = project.getJsonResult(projectId, scanResultId);
                RemoteFileUtils.saveReport(launcher, listener, workspace.getRemote(),
                        "issues.json", FileUtils.readFileToByteArray(json), verbose);
            }

            // Step is failed if scan aborted or failed (i.e. because of license problems)
            failed |= !Stage.DONE.equals(stage);
            if (Stage.ABORTED.equals(stage))
                reason = Messages.plugin_result_ast_aborted();
            else if (Stage.FAILED.equals(stage))
                reason = Messages.plugin_result_ast_failed();
            else
                reason = Messages.plugin_result_ast_success();

            // Step also failed if policy assessment fails
            // TODO: Swap REJECTED/CONFIRMED states
            //  when https://jira.ptsecurity.com/browse/AI-4866 will be fixed
            if (!failed) {
                failed |= PolicyState.CONFIRMED.equals(state.getStatistic().getPolicyState());
                // If scan is done, than the only reason to fail is policy violation
                if (failed)
                    reason = Messages.plugin_result_ast_policy_failed();
                else if (PolicyState.REJECTED.equals(state.getStatistic().getPolicyState()))
                    reason = Messages.plugin_result_ast_policy_success();
                else
                    reason = Messages.plugin_result_ast_policy_empty();
            }

            if (failIfFailed && failed)
                throw new AbortException(reason);
            if (failIfUnstable && unstable)
                 throw new AbortException(Messages.plugin_result_ast_unstable());
            project.info(reason);
        } catch (InterruptedException e) {
            if (null != scanResultId) project.stop(scanResultId);
            throw e;
        } catch (ApiException e) {
            project.severe(Messages.plugin_result_ast_error(e.getMessage()), e);
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