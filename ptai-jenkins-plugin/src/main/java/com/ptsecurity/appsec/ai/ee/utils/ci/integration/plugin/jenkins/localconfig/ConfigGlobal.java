package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.Config;
import hudson.Extension;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class ConfigGlobal extends ConfigBase {
    public static final ConfigBaseDescriptor DESCRIPTOR = new Descriptor();

    @Getter
    private final String configName;

    @DataBoundConstructor
    public ConfigGlobal(final String configName) {
        this.configName = configName;
    }

    @Extension
    @Symbol("configGlobal")
    public static class Descriptor extends ConfigBaseDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_config_global_label();
        }

        public ListBoxModel doFillConfigNameItems() {
            PluginDescriptor desc = Jenkins.get().getDescriptorByType(PluginDescriptor.class);
            ListBoxModel model = new ListBoxModel();
            for (Config globalConfig : desc.getGlobalConfigs())
                model.add(globalConfig.getConfigName(), globalConfig.getConfigName());
            return model;
        }
    }
}
