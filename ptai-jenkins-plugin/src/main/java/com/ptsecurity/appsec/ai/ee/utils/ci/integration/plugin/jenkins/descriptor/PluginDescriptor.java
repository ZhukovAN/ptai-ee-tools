package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.LegacyConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.SlimConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigSlimCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigBase;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigLegacyCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.BaseConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.SlimServerSettings;
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
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.bind.JavaScriptMethod;
import org.parboiled.common.StringUtils;

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

    public BaseConfig getConfig(final String configName) {
        for (BaseConfig globalConfig : globalConfigs) {
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
            globalConfigs.replaceBy(request.bindJSONToList(BaseConfig.class, jsonConfigs));
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
            final String serverLegacyUrl,
            final String serverLegacyCredentialsId,
            final String jenkinsServerUrl,
            final String jenkinsJobName,
            final String serverSlimUrl,
            final String serverSlimCredentialsId,
            final String configName) {
        FormValidation res = null;
        ScanSettingsUi.Descriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class);
        ScanSettingsManual.Descriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.Descriptor.class);
        ConfigGlobal.Descriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.Descriptor.class);
        ConfigLegacyCustom.Descriptor configLegacyDescriptor = Jenkins.get().getDescriptorByType(ConfigLegacyCustom.Descriptor.class);
        ConfigSlimCustom.Descriptor configSlimDescriptor = Jenkins.get().getDescriptorByType(ConfigSlimCustom.Descriptor.class);

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
            } else if (configLegacyDescriptor.getDisplayName().equals(selectedConfig)) {
                LegacyServerSettingsDescriptor legacyServerSettingsDescriptor = Jenkins.get().getDescriptorByType(LegacyServerSettingsDescriptor.class);
                res = legacyServerSettingsDescriptor.doCheckServerUrl(serverLegacyUrl);
                if (FormValidation.Kind.OK != res.kind) break;
                res = legacyServerSettingsDescriptor.doCheckJenkinsServerUrl(jenkinsServerUrl);
                if (FormValidation.Kind.OK != res.kind) break;
                res = legacyServerSettingsDescriptor.doCheckJenkinsJobName(jenkinsJobName);
                if (FormValidation.Kind.OK != res.kind) break;
                if (!Validator.doCheckFieldNotEmpty(serverLegacyCredentialsId)) {
                    res = Validator.error(new PtaiClientException(Messages.validator_check_serverCredentialsId_empty()));
                    break;
                }
            } else if (configSlimDescriptor.getDisplayName().equals(selectedConfig)) {
                SlimServerSettingsDescriptor slimServerSettingsDescriptor = Jenkins.get().getDescriptorByType(SlimServerSettingsDescriptor.class);
                res = slimServerSettingsDescriptor.doCheckServerUrl(serverSlimUrl);
                if (FormValidation.Kind.OK != res.kind) break;
                if (!Validator.doCheckFieldNotEmpty(serverSlimCredentialsId)) {
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
            @QueryParameter("serverLegacyUrl") final String serverLegacyUrl,
            @QueryParameter("serverLegacyCredentialsId") final String serverLegacyCredentialsId,
            @QueryParameter("jenkinsServerUrl") final String jenkinsServerUrl,
            @QueryParameter("jenkinsJobName") final String jenkinsJobName,
            @QueryParameter("serverSlimUrl") final String serverSlimUrl,
            @QueryParameter("serverSlimCredentialsId") final String serverSlimCredentialsId,
            @QueryParameter("userName") final String userName,
            @QueryParameter("apiToken") final String apiToken,
            @QueryParameter("configName") final String configName) {
        FormValidation res = doTestProjectFields(
                selectedScanSettings, selectedConfig,
                jsonSettings, jsonPolicy,
                projectName,
                serverLegacyUrl, serverLegacyCredentialsId, jenkinsServerUrl, jenkinsJobName,
                serverSlimUrl, serverSlimCredentialsId,
                configName);
        if (FormValidation.Kind.OK != res.kind) return res;

        ScanSettingsUi.Descriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class);
        ScanSettingsManual.Descriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.Descriptor.class);
        ConfigGlobal.Descriptor configGlobalDescriptor = Jenkins.get().getDescriptorByType(ConfigGlobal.Descriptor.class);
        ConfigLegacyCustom.Descriptor configLegacyCustomDescriptor = Jenkins.get().getDescriptorByType(ConfigLegacyCustom.Descriptor.class);
        ConfigSlimCustom.Descriptor configSlimCustomDescriptor = Jenkins.get().getDescriptorByType(ConfigSlimCustom.Descriptor.class);
        try {
            LegacyCredentials legacyCredentials = null;
            SlimCredentials slimCredentials = null;
            String realServerUrl = null;

            if (configGlobalDescriptor.getDisplayName().equals(selectedConfig)) {
                // Settings are defined globally, job just refers them using configName
                BaseConfig base = getConfig(configName);
                // What is the type of global config?
                if (base instanceof LegacyConfig) {
                    LegacyServerSettings legacyServerSettings = ((LegacyConfig) base).getLegacyServerSettings();
                    legacyCredentials = LegacyCredentialsImpl.getCredentialsById(item, legacyServerSettings.getServerLegacyCredentialsId());
                    realServerUrl = legacyServerSettings.getServerLegacyUrl();
                } else {
                    SlimServerSettings slimServerSettings = ((SlimConfig) base).getSlimServerSettings();
                    slimCredentials = SlimCredentialsImpl.getCredentialsById(item, slimServerSettings.getServerSlimCredentialsId());
                    realServerUrl = slimServerSettings.getServerSlimUrl();
                }
            } else if (configLegacyCustomDescriptor.getDisplayName().equals(selectedConfig)) {
                legacyCredentials = LegacyCredentialsImpl.getCredentialsById(item, serverLegacyCredentialsId);
                realServerUrl = serverLegacyUrl;
            } else {
                slimCredentials = SlimCredentialsImpl.getCredentialsById(item, serverSlimCredentialsId);
                realServerUrl = serverSlimUrl;
            }
            // Depending on settings real project name may be defined using UI or JSON
            boolean selectedScanSettingsUi = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class).getDisplayName().equals(selectedScanSettings);
            String realProjectName = selectedScanSettingsUi
                    ? projectName
                    : JsonSettingsVerifier.verify(jsonSettings).getProjectName();
            UUID projectId = (null != legacyCredentials)
                    ? searchProjectWithLegacyConfig(realProjectName, realServerUrl, legacyCredentials, selectedScanSettingsUi)
                    : searchProjectWithSlimConfig(realProjectName, realServerUrl, slimCredentials, selectedScanSettingsUi);
            if (null == projectId) {
                // For manual defined (JSON) scan settings lack of project isn't a crime itself, just show warning
                // instead of error
                return selectedScanSettingsUi
                        ? FormValidation.error(Messages.validator_test_ptaiProject_notfound())
                        : FormValidation.warning(Messages.validator_test_ptaiProject_notfound());
            } else
                return FormValidation.ok(Messages.validator_test_ptaiProject_success(projectId.toString().substring(0, 4)));
        } catch (Exception e) {
            return Validator.error(e);
        }

    }

    protected UUID searchProjectWithSlimConfig(
            String projectName, String serverSlimUrl,
            SlimCredentials slimCredentials, boolean selectedScanSettingsUi) throws Exception {
        Client client = new Client();
        client.setUrl(serverSlimUrl);
        client.setClientId(Plugin.CLIENT_ID);
        client.setClientSecret(Plugin.CLIENT_SECRET);
        client.setUserName(slimCredentials.getUserName());
        client.setPassword(slimCredentials.getPassword().getPlainText());
        if (!org.apache.commons.lang.StringUtils.isEmpty(slimCredentials.getServerCaCertificates()))
            client.setCaCertsPem(slimCredentials.getServerCaCertificates());
        client.init();
        return client.getDiagnosticApi().getProject(projectName);
    }

    protected UUID searchProjectWithLegacyConfig(
            String projectName, String serverLegacyUrl,
            LegacyCredentials legacyCredentials,
            boolean selectedScanSettingsUi) throws Exception {
        PtaiProject ptaiProject = new PtaiProject();
        ptaiProject.setUrl(serverLegacyUrl);
        ptaiProject.setKeyPem(legacyCredentials.getClientCertificate());
        ptaiProject.setKeyPassword(legacyCredentials.getClientKey().getPlainText());
        ptaiProject.setCaCertsPem(legacyCredentials.getServerCaCertificates());

        // Connect to PT AI server and try to authenticate
        String token = ptaiProject.init();
        if (StringUtils.isEmpty(token))
            throw new PtaiServerException(Messages.validator_test_ptaiServer_auth_failed(), null);

        // Search for project to be sure everything is OK
        ptaiProject.setName(projectName);
        return ptaiProject.searchProject();
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
