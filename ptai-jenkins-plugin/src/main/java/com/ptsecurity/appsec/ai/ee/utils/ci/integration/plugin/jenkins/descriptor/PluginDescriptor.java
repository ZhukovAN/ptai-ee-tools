package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.Config;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigBase;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigCustom;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkMode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync;
import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.CopyOnWriteList;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

@Slf4j
@Extension
@Symbol("ptaiAst")
public class PluginDescriptor extends BuildStepDescriptor<Builder> {

    private final CopyOnWriteList<Config> globalConfigs = new CopyOnWriteList<>();

    @Getter
    private String advancedSettings = null;

    public List<Config> getGlobalConfigs() {
        return globalConfigs.getView();
    }

    public TransferDescriptor getTransferDescriptor() {
        return Jenkins.get().getDescriptorByType(TransferDescriptor.class);
    }

    public PluginDescriptor() {
        super(Plugin.class);
        load();
    }

    @Override
    public boolean isApplicable(Class<? extends AbstractProject> jobType) {
        return true;
    }

    public Config getConfig(final String name) {
        return globalConfigs.getView().stream()
                .filter(cfg -> cfg.getConfigName().equals(name))
                .findAny().orElse(null);
    }

    @Override
    public boolean configure(StaplerRequest request, JSONObject formData) {
        // noinspection ConstantConditions
        do {
            globalConfigs.clear();
            if (formData.isEmpty()) break;

            Object jsonConfigs = formData.get("globalConfigs");
            if (null == jsonConfigs) break;

            if (!(jsonConfigs instanceof JSONArray) && !(jsonConfigs instanceof JSONObject)) break;
            if ((jsonConfigs instanceof JSONArray) && ((JSONArray) jsonConfigs).isEmpty()) break;
            if ((jsonConfigs instanceof JSONObject) && ((JSONObject) jsonConfigs).isEmpty()) break;

            globalConfigs.replaceBy(request.bindJSONToList(Config.class, jsonConfigs));

            advancedSettings = formData.getString("advancedSettings");
        } while (false);

        save();
        return true;
    }

    /**
     * Method checks if AST job step settings are correct.
     * It doesn't checks PT AI server availability, project existence etc.
     * @param scanSettings AST settings mode: UI- or JSON-based
     * @param config Config mode: global- or task-defined
     * @param jsonSettings JSON-defined AST settings
     * @param jsonPolicy JSON-defined policy
     * @param projectName PT AI project name for UI-defined AST settings mode
     * @param serverUrl PT AI server URL for task-defined private config
     * @param serverCredentialsId PT AI credentials Id for task-defined private config
     * @param configName Global configuration name
     * @return Validation result
     */
    public FormValidation doTestProjectFields(
            final ScanSettings scanSettings, final ConfigBase config,
            final String jsonSettings, final String jsonPolicy,
            final String projectName,
            final String serverUrl, final String serverCredentialsId,
            final String configName) {
        FormValidation res = null;
        // noinspection ConstantConditions
        do {
            if (scanSettings instanceof ScanSettingsUi) {
                ScanSettingsUi.Descriptor scanSettingsUiDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class);
                res = scanSettingsUiDescriptor.doCheckProjectName(projectName);
                if (FormValidation.Kind.ERROR == res.kind) break;
            } else if (scanSettings instanceof  ScanSettingsManual) {
                ScanSettingsManual.Descriptor scanSettingsManualDescriptor = Jenkins.get().getDescriptorByType(ScanSettingsManual.Descriptor.class);
                res = scanSettingsManualDescriptor.doCheckJsonSettings(jsonSettings);
                if (FormValidation.Kind.ERROR == res.kind) break;
                res = scanSettingsManualDescriptor.doCheckJsonPolicy(jsonPolicy);
                if (FormValidation.Kind.ERROR == res.kind) break;
            }
            if (config instanceof ConfigGlobal) {
                if (!Validator.doCheckFieldNotEmpty(configName)) {
                    res = Validator.error(Resources.i18n_ast_settings_config_global_name_message_empty());
                    break;
                }
            } else if (config instanceof ConfigCustom) {
                ServerSettingsDescriptor serverSettingsDescriptor = Jenkins.get().getDescriptorByType(ServerSettingsDescriptor.class);
                res = serverSettingsDescriptor.doCheckServerUrl(serverUrl);
                if (FormValidation.Kind.ERROR == res.kind) break;
                if (!Validator.doCheckFieldNotEmpty(serverCredentialsId)) {
                    res = Validator.error(Resources.i18n_ast_settings_server_credentials_message_empty());
                    break;
                }
            }
        } while (false);
        return res;
    }

    @Override
    @Nonnull
    public String getDisplayName() {
        return Resources.i18n_ast_plugin_label();
    }

    @SuppressWarnings("unused")
    public static List<ConfigBase.ConfigBaseDescriptor> getConfigDescriptors() {
        return ConfigBase.getAll();
    }

    @SuppressWarnings("unused")
    public static ConfigBase.ConfigBaseDescriptor getDefaultConfigDescriptor() {
        return Jenkins.get().getDescriptorByType(ConfigGlobal.Descriptor.class);
    }

    @SuppressWarnings("unused")
    public static List<ScanSettings.ScanSettingsDescriptor> getScanSettingsDescriptors() {
        return ScanSettings.getAll();
    }

    @SuppressWarnings("unused")
    public static ScanSettings.ScanSettingsDescriptor getDefaultScanSettingsDescriptor() {
        return Jenkins.get().getDescriptorByType(ScanSettingsUi.Descriptor.class);
    }

    public static List<WorkMode.WorkModeDescriptor> getWorkModeDescriptors() {
        return WorkMode.getAll();
    }

    @SuppressWarnings("unused")
    public static WorkMode.WorkModeDescriptor getDefaultWorkModeDescriptor() {
        return Jenkins.get().getDescriptorByType(WorkModeSync.Descriptor.class);
    }

    protected static Map<String, String> versionInfo = null;

    @NonNull
    public static String getVersion() {
        Map<String, String> version = getVersionInfo();
        StringBuilder builder = new StringBuilder();
        if (StringUtils.isNotEmpty(version.get("Implementation-Version")))
            builder.append(" v.").append(version.get("Implementation-Version"));
        if (StringUtils.isNotEmpty(version.get("Implementation-Git-Hash")))
            builder.append("-").append(version.get("Implementation-Git-Hash"));
        if (StringUtils.isNotEmpty(version.get("Build-Time")))
            builder.append(" built on ").append(version.get("Build-Time"));
        return builder.toString();
    }

    public static Map<String, String> getVersionInfo() {
        if (null != versionInfo) return versionInfo;
        versionInfo = new HashMap<>();
        try {
            Enumeration<URL> res = PluginDescriptor.class.getClassLoader().getResources("META-INF/MANIFEST.MF");
            while (res.hasMoreElements()) {
                URL url = res.nextElement();
                Manifest manifest = new Manifest(url.openStream());

                if (!isApplicableManifest(manifest)) continue;
                Attributes attr = manifest.getMainAttributes();
                versionInfo.put("Implementation-Version", get(attr, "Implementation-Version").toString());
                versionInfo.put("Implementation-Git-Hash", get(attr, "Implementation-Git-Hash").toString());
                versionInfo.put("Build-Time", get(attr, "Build-Time").toString());
                break;
            }
        } catch (IOException e) {
            log.warn("Failed to get build info from plugin metadata");
            log.debug("Exception details", e);
        }
        return versionInfo;
    }

    @SuppressWarnings("unused")
    public FormValidation doCheckAdvancedSettings(@QueryParameter String value) {
        return Validator.doCheckFieldAdvancedSettings(value, Resources.i18n_ast_settings_advanced_message_invalid());
    }

    private static boolean isApplicableManifest(Manifest manifest) {
        Attributes attributes = manifest.getMainAttributes();
        return "com.ptsecurity.appsec.ai.ee.utils.ci.integration".equals(get(attributes, "Implementation-Vendor-Id"));
    }

    private static Object get(Attributes attributes, String key) {
        return attributes.get(new Attributes.Name(key));
    }
}
