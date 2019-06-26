package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.GlobalConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import hudson.Extension;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class ConfigGlobal extends ConfigBase {
    @Extension
    public static final ConfigDescriptor DESCRIPTOR = new ConfigGlobalDescriptor();

    @Getter
    private final String configName;

    @DataBoundConstructor
    public ConfigGlobal(final String configName) {
        this.configName = configName;
    }

    @Symbol("ConfigGlobal")
    @Extension
    public static class ConfigGlobalDescriptor extends ConfigDescriptor {
        @Override
        public String getDisplayName() {
            return "ConfigGlobal";
        }

        public ListBoxModel doFillConfigNameItems() {
            PluginDescriptor desc = Jenkins.get().getDescriptorByType(PluginDescriptor.class);
            ListBoxModel model = new ListBoxModel();
            for (GlobalConfig globalConfig : desc.getGlobalConfigs())
                model.add(globalConfig.getConfigName(), globalConfig.getConfigName());
            return model;
        }
    }
}
