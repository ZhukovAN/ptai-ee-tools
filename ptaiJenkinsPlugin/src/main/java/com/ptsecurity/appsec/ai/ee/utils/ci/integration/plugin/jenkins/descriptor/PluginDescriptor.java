package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.GlobalConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config.Config;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config.ConfigCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import hudson.Extension;
import hudson.Util;
import hudson.model.*;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.CopyOnWriteList;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.bind.JavaScriptMethod;
import org.parboiled.common.StringUtils;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Extension
@Symbol("ptaiUiSast")
public class PluginDescriptor extends BuildStepDescriptor<Builder> {

    private final CopyOnWriteList<GlobalConfig> globalConfigs = new CopyOnWriteList<>();

    public List<GlobalConfig> getGlobalConfigs() {
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

    public GlobalConfig getConfig(final String configName) {
        for (GlobalConfig globalConfig : globalConfigs) {
            if (globalConfig.getConfigName().equals(configName))
                return globalConfig;
        }
        return null;
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
            globalConfigs.replaceBy(request.bindJSONToList(GlobalConfig.class, jsonConfigs));
        } while (false);
        save();
        return true;
    }

    public FormValidation doTestProjectFields(
            final String selectedScanSettings,
            final String selectedConfig,
            final String jsonSettings,
            final String jsonPolicy,
            final String projectName,
            final String serverUrl,
            final String serverCredentialsId,
            final String jenkinsServerUrl,
            final String jenkinsJobName,
            final String configName) {
        FormValidation res = null;
        ScanSettingsUi.ScanSettingsUiDescriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.ScanSettingsUiDescriptor.class);
        ScanSettingsManual.ScanSettingsManualDescriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.ScanSettingsManualDescriptor.class);
        ConfigGlobal.ConfigGlobalDescriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.ConfigGlobalDescriptor.class);
        ConfigCustom.ConfigCustomDescriptor configCustomDescriptor = Jenkins.get().getDescriptorByType(ConfigCustom.ConfigCustomDescriptor.class);

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
                    res = Validator.error(new PtaiClientException(Messages.validator_check_configName_empty()));
                    break;
                }
            } else if (configCustomDescriptor.getDisplayName().equals(selectedConfig)) {
                ServerSettingsDescriptor serverSettingsDescriptor = Jenkins.get().getDescriptorByType(ServerSettingsDescriptor.class);
                res = serverSettingsDescriptor.doCheckServerUrl(serverUrl);
                if (FormValidation.Kind.OK != res.kind) break;
                res = serverSettingsDescriptor.doCheckJenkinsServerUrl(jenkinsServerUrl);
                if (FormValidation.Kind.OK != res.kind) break;
                res = serverSettingsDescriptor.doCheckJenkinsJobName(jenkinsJobName);
                if (FormValidation.Kind.OK != res.kind) break;
                if (!Validator.doCheckFieldNotEmpty(serverCredentialsId)) {
                    res = Validator.error(new PtaiClientException(Messages.validator_check_serverCredentialsId_empty()));
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
            @QueryParameter("jenkinsServerUrl") final String jenkinsServerUrl,
            @QueryParameter("jenkinsJobName") final String jenkinsJobName,
            @QueryParameter("userName") final String userName,
            @QueryParameter("apiToken") final String apiToken,
            @QueryParameter("configName") final String configName) {
        ScanSettingsUi.ScanSettingsUiDescriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.ScanSettingsUiDescriptor.class);
        ScanSettingsManual.ScanSettingsManualDescriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.ScanSettingsManualDescriptor.class);
        ConfigGlobal.ConfigGlobalDescriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.ConfigGlobalDescriptor.class);
        ConfigCustom.ConfigCustomDescriptor configCustomDescriptor = Jenkins.get().getDescriptorByType(ConfigCustom.ConfigCustomDescriptor.class);
        ServerSettings serverSettings = null;

        FormValidation res = doTestProjectFields(
                selectedScanSettings, selectedConfig,
                jsonSettings, jsonPolicy,
                projectName,
                serverUrl, serverCredentialsId, jenkinsServerUrl, jenkinsJobName, configName);
        if (FormValidation.Kind.OK != res.kind) return res;
        if (configGlobalDescriptor.getDisplayName().equals(selectedConfig))
            serverSettings = getConfig(configName).getServerSettings();

        try {
            ServerCredentials serverCredentials = (null != serverSettings)
                    ? ServerCredentialsImpl.getCredentialsById(item, serverSettings.getServerCredentialsId())
                    : ServerCredentialsImpl.getCredentialsById(item, serverCredentialsId);

            PtaiProject ptaiProject = new PtaiProject();
            ptaiProject.setUrl(null != serverSettings ? serverSettings.getServerUrl() : serverUrl);
            ptaiProject.setKeyPem(serverCredentials.getClientCertificate());
            ptaiProject.setKeyPassword(serverCredentials.getClientKey().getPlainText());
            ptaiProject.setCaCertsPem(serverCredentials.getServerCaCertificates());

            // Connect to PT AI server
            //
            // Try to authenticate
            String token = ptaiProject.init();
            if (StringUtils.isEmpty(token))
                throw new PtaiServerException(Messages.validator_test_ptaiServer_auth_failed(), null);

            // Search for project

            ptaiProject.setName(Util.fixEmptyAndTrim(scanSettingsUiDescriptor.getDisplayName().equals(selectedScanSettings) ?
                    projectName : JsonSettingsVerifier.verify(jsonSettings).ProjectName));
            UUID projectId = ptaiProject.searchProject();
            if (null == projectId) {
                /*
                if (scanSettingsUiDescriptor.getDisplayName().equals(selectedScanSettings))
                    return FormValidation.error(Messages.validator_test_ptaiProject_notfound());
                else
                    return FormValidation.warning(Messages.validator_test_ptaiProject_notfound());
                 */
                return FormValidation.error(Messages.validator_test_ptaiProject_notfound());
            } else
                return FormValidation.ok(Messages.validator_test_ptaiProject_success(projectId.toString().substring(0, 4)));
        } catch (Exception e) {
            return Validator.error(e);
        }
    }

    public String getDisplayName() {
        return Messages.captions_plugin_displayname();
    }

    public static List<Config.ConfigDescriptor> getConfigDescriptors() {
        return Config.getAll();
    }

    public static Config.ConfigDescriptor getDefaultConfigDescriptor() {
        return ConfigGlobal.DESCRIPTOR;
    }

    public static List<ScanSettings.ScanSettingsDescriptor> getScanSettingsDescriptors() {
        return ScanSettings.getAll();
    }

    public static ScanSettings.ScanSettingsDescriptor getDefaultScanSettingsDescriptor() {
        return ScanSettingsUi.DESCRIPTOR;
    }
}
