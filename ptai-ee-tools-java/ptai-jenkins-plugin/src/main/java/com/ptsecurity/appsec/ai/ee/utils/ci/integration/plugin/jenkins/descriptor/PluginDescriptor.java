package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.V36Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.V36CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.V36Config;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigV36Custom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.V36ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigBase;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.BaseConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.exceptions.ApiException;
import hudson.Extension;
import hudson.model.*;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.CopyOnWriteList;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.NonNull;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.util.List;
import java.util.UUID;

@Extension
@Symbol("ptaiUiSast")
public class PluginDescriptor extends BuildStepDescriptor<Builder> {

    private final CopyOnWriteList<BaseConfig> globalConfigs = new CopyOnWriteList<>();

    public List<BaseConfig> getGlobalConfigs() {
        return globalConfigs.getView();
    }

    public TransferDescriptor getTransferDescriptor() {
        return Jenkins.get().getDescriptorByType(TransferDescriptor.class);
    }

    public PluginDescriptor() {
        super(Plugin.class);
        load();
    }

    private int lastElementId = 0;

    @JavaScriptMethod
    public synchronized String createElementId() {
        return "ptaiJenkinsPlugin_" + String.valueOf(lastElementId++);
    }

    @Override
    public boolean isApplicable(Class<? extends AbstractProject> jobType) {
        return true;
    }

    public BaseConfig getConfig(final String name) {
        return globalConfigs.getView().stream()
                .filter(cfg -> cfg.getConfigName().equals(name))
                .findAny().orElse(null);
    }

    @Override
    public boolean configure(StaplerRequest request, JSONObject formData) throws FormException {
        do {
            globalConfigs.clear();
            if (formData.isEmpty()) break;
            Object jsonConfigs = formData.get("globalConfigs");
            if (null == jsonConfigs) break;
            if (!(jsonConfigs instanceof JSONArray) && !(jsonConfigs instanceof JSONObject)) break;
            if ((jsonConfigs instanceof JSONArray) && ((JSONArray) jsonConfigs).isEmpty()) break;
            if ((jsonConfigs instanceof JSONObject) && ((JSONObject) jsonConfigs).isEmpty()) break;
            globalConfigs.replaceBy(request.bindJSONToList(BaseConfig.class, jsonConfigs));
        } while (false);
        save();
        return true;
    }

    /**
     * Method checks if AST job step settings are correct.
     * It doesn't checks PT AI server availability, project existence etc.
     * @param selectedScanSettings AST settings mode: UI- or JSON-based
     * @param selectedConfig Config mode: global- or task-defined
     * @param jsonSettings JSON-defined AST settings
     * @param jsonPolicy JSON-defined policy
     * @param projectName PT AI project name for UI-defined AST settings mode
     * @param serverUrl PT AI server URL for task-defined private config
     * @param serverCredentialsId PT AI credentials Id for task-defined private config
     * @param configName Global configuration name
     * @return Validation result
     */
    public FormValidation doTestProjectFields(
            final String selectedScanSettings, final String selectedConfig,
            final String jsonSettings, final String jsonPolicy,
            final String projectName,
            final String serverUrl, final String serverCredentialsId,
            final String configName) {
        FormValidation res = null;
        ScanSettingsUi.Descriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class);
        ScanSettingsManual.Descriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.Descriptor.class);
        ConfigGlobal.Descriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.Descriptor.class);
        ConfigV36Custom.Descriptor configLocalDescriptor = Jenkins.get().getDescriptorByType(ConfigV36Custom.Descriptor.class);

        do {
            if (scanSettingsUiDescriptor.getDisplayName().equals(selectedScanSettings)) {
                res = scanSettingsUiDescriptor.doCheckProjectName(projectName);
                if (FormValidation.Kind.OK != res.kind) break;
            } else if (scanSettingsManualDescriptor.getDisplayName().equals(selectedScanSettings)) {
                res = scanSettingsManualDescriptor.doCheckJsonSettings(jsonSettings);
                if (FormValidation.Kind.OK != res.kind) break;
                res = scanSettingsManualDescriptor.doCheckJsonPolicy(jsonPolicy);
                if (FormValidation.Kind.OK != res.kind) break;
            }
            if (configGlobalDescriptor.getDisplayName().equals(selectedConfig)) {
                if (!Validator.doCheckFieldNotEmpty(configName)) {
                    res = Validator.error(Messages.validator_check_configName_empty());
                    break;
                }
            } else if (configLocalDescriptor.getDisplayName().equals(selectedConfig)) {
                V36ServerSettingsDescriptor serverSettingsDescriptor = Jenkins.get().getDescriptorByType(V36ServerSettingsDescriptor.class);
                res = serverSettingsDescriptor.doCheckServerUrl(serverUrl);
                if (FormValidation.Kind.OK != res.kind) break;
                if (!Validator.doCheckFieldNotEmpty(serverCredentialsId)) {
                    res = Validator.error(Messages.validator_check_serverCredentialsId_empty());
                    break;
                }
            }
        } while (false);
        return res;
    }

    public FormValidation doTestProject(
            @AncestorInPath Item item,
            @QueryParameter("selectedScanSettings") final String selectedScanSettings,
            @QueryParameter("selectedConfig") final String selectedConfig,
            @QueryParameter("jsonSettings") final String jsonSettings,
            @QueryParameter("jsonPolicy") final String jsonPolicy,
            @QueryParameter("projectName") final String projectName,
            @QueryParameter("serverUrl") final String serverUrl,
            @QueryParameter("serverCredentialsId") final String serverCredentialsId,
            @QueryParameter("apiToken") final String apiToken,
            @QueryParameter("configName") final String configName) {
        FormValidation res = doTestProjectFields(
                selectedScanSettings, selectedConfig,
                jsonSettings, jsonPolicy,
                projectName,
                serverUrl, serverCredentialsId,
                configName);
        if (FormValidation.Kind.OK != res.kind) return res;

        ConfigGlobal.Descriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.Descriptor.class);
         try {
            V36Credentials credentials;
            String realServerUrl;

            if (configGlobalDescriptor.getDisplayName().equals(selectedConfig)) {
                // Settings are defined globally, job just refers them using configName
                BaseConfig base = getConfig(configName);
                // What is the type of global config?
                V36ServerSettings serverSettings = ((V36Config) base).getServerSettings();
                credentials = V36CredentialsImpl.getCredentialsById(item, serverSettings.getServerCredentialsId());
                realServerUrl = serverSettings.getServerUrl();
            } else {
                credentials = V36CredentialsImpl.getCredentialsById(item, serverCredentialsId);
                realServerUrl = serverUrl;
            }
            // Depending on settings real project name may be defined using UI or JSON
            boolean selectedScanSettingsUi = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class).getDisplayName().equals(selectedScanSettings);
            String realProjectName = selectedScanSettingsUi
                    ? projectName
                    : JsonSettingsVerifier.verify(jsonSettings).getProjectName();
            UUID projectId = searchProject(realProjectName, realServerUrl, credentials);
            if (null == projectId) {
                // For manual defined (JSON) scan settings lack of project isn't a crime itself, just show warning
                // instead of error
                return selectedScanSettingsUi
                        ? FormValidation.error(Messages.validator_test_ptaiProject_notfound())
                        : FormValidation.warning(Messages.validator_test_ptaiProject_notfound());
            } else
                return FormValidation.ok(Messages.validator_test_ptaiProject_success(projectId.toString().substring(0, 4)));
        } catch (ApiException e) {
            return Validator.error(e);
        }
    }

    protected UUID searchProject(
            @NonNull final String name, @NonNull final String url,
            @NonNull final V36Credentials credentials) throws ApiException {
        Project project = new Project(name);
        project.setUrl(url);
        project.setToken(credentials.getPassword().getPlainText());
        if (StringUtils.isNotEmpty(credentials.getServerCaCertificates()))
            project.setCaCertsPem(credentials.getServerCaCertificates());
        project.init();
        return project.searchProject();
    }

    public String getDisplayName() {
        return Messages.captions_plugin_displayName();
    }

    public static List<ConfigBase.ConfigBaseDescriptor> getConfigDescriptors() {
        return ConfigBase.getAll();
    }

    public static ConfigBase.ConfigBaseDescriptor getDefaultConfigDescriptor() {
        return ConfigGlobal.DESCRIPTOR;
    }

    public static List<ScanSettings.ScanSettingsDescriptor> getScanSettingsDescriptors() {
        return ScanSettings.getAll();
    }

    public static ScanSettings.ScanSettingsDescriptor getDefaultScanSettingsDescriptor() {
        return ScanSettingsUi.DESCRIPTOR;
    }
}
