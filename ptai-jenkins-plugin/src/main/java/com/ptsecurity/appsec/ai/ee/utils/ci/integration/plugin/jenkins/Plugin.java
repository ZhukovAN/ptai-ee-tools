package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobMultipleResults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.Config;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigBase;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.BaseReport;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildEnv;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildInfo;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkMode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeAsync;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
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
import java.io.IOException;
import java.util.*;

import static org.apache.commons.lang3.StringUtils.trimToNull;

@Slf4j
@ToString
public class Plugin extends Builder implements SimpleBuildStep {
    private static final String CONSOLE_PREFIX = AbstractTool.DEFAULT_LOG_PREFIX;

    @Getter
    private final ConfigBase config;

    @Getter
    private final com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings scanSettings;

    @Getter
    private final WorkMode workMode;

    @Getter
    private final boolean verbose;

    @Getter
    private final boolean fullScanMode;

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
                  final boolean verbose,
                  final boolean fullScanMode,
                  final ArrayList<Transfer> transfers) {
        this.scanSettings = scanSettings;
        this.config = config;
        this.workMode = workMode;
        this.verbose = verbose;
        this.fullScanMode = fullScanMode;
        this.transfers = transfers;
    }

    private TreeMap<String, String> getEnvironmentVariables(final Run<?, ?> build, final TaskListener listener) {
        try {
            final TreeMap<String, String> env = build.getEnvironment(listener);
            if (build instanceof AbstractBuild<?,?>) {
                AbstractBuild<?, ?> abstractBuild = (AbstractBuild<?, ?>) build;
                env.putAll(abstractBuild.getBuildVariables());
            }
            return env;
        } catch (Exception e) {
            throw new RuntimeException(Resources.i18n_ast_result_status_failed_environment(), e);
        }
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
            AiProjScanSettings scanSettings = JsonSettingsHelper.verify(jsonSettings);
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
        boolean serverInsecure;

        if (config instanceof ConfigGlobal) {
            // Settings are defined globally, job just refers them using configName
            configName = ((ConfigGlobal) config).getConfigName();
            Config base = descriptor.getConfig(configName);
            serverSettings = base.getServerSettings();
            credentialsId = serverSettings.getServerCredentialsId();
            credentials = CredentialsImpl.getCredentialsById(item, credentialsId);
            serverUrl = serverSettings.getServerUrl();
            serverInsecure = serverSettings.isServerInsecure();
        } else {
            ConfigCustom configCustom = (ConfigCustom) config;
            credentialsId = configCustom.getServerSettings().getServerCredentialsId();
            credentials = CredentialsImpl.getCredentialsById(item, credentialsId);
            serverUrl = configCustom.getServerSettings().getServerUrl();
            serverInsecure = configCustom.getServerSettings().isServerInsecure();
        }

        check = descriptor.doTestProjectFields(
                selectedScanSettings,
                selectedConfig,
                jsonSettings, jsonPolicy,
                projectName,
                serverUrl, credentialsId, serverInsecure, configName);
        if (FormValidation.Kind.OK != check.kind)
            throw new AbortException(check.getMessage());
        // TODO: Implement scan node support when PT AI will be able to
        // String node = StringUtils.isEmpty(nodeName) ? Base.DEFAULT_PTAI_NODE_NAME : nodeName;
        Reports reports = null;
        if (workMode instanceof WorkModeSync) {
            WorkModeSync workModeSync = (WorkModeSync) workMode;
            if (null != workModeSync.getReports())
                reports = BaseReport.convert(workModeSync.getReports());
        }

        JenkinsAstJob job = JenkinsAstJob.builder()
                .projectName(selectedScanSettingsUi ? projectName : null)
                .settings(selectedScanSettingsUi ? null : jsonSettings)
                .policy(selectedScanSettingsUi ?  null : jsonPolicy)
                .console(listener.getLogger())
                .verbose(verbose)
                .prefix(CONSOLE_PREFIX)
                .connectionSettings(ConnectionSettings.builder()
                        .url(serverUrl)
                        .token(credentials.getToken().getPlainText())
                        .caCertsPem(credentials.getServerCaCertificates())
                        .insecure(serverInsecure)
                        .build())
                .async(workMode instanceof WorkModeAsync)
                .failIfFailed(failIfFailed)
                .failIfUnstable(failIfUnstable)
                .run(build)
                .workspace(workspace)
                .launcher(launcher)
                .listener(listener)
                .buildInfo(buildInfo)
                .transfers(transfers)
                .reports(reports)
                .fullScanMode(fullScanMode)
                .build();
        job.info("JenkinsAstJob created: %s", job.toString());
        if (!AbstractJob.JobExecutionResult.SUCCESS.equals(job.execute()))
            throw new AbortException(Resources.i18n_ast_result_status_failed());
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

    /*
    @Override
    public Action getProjectAction(AbstractProject<?, ?> project) {
        return new AstJobMultipleResults(project);
    }
    */

    List<Action> projectActions = null;

    @Override
    public Collection<Action> getProjectActions(AbstractProject<?, ?> project) {
        if (null != projectActions) return projectActions;
        projectActions = new ArrayList<>();
        projectActions.add(new AstJobMultipleResults(project));
        // TODO: Implement project actions and uncomment this
        // projectActions.add(new AstJobTableResults(project.getName()));
        return projectActions;
    }
}