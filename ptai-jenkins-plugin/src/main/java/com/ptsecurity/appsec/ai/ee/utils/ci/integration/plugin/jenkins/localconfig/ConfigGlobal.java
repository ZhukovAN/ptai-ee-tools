package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.Config;
import hudson.Extension;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class ConfigGlobal extends ConfigBase {
    @Extension
    public static final ConfigBaseDescriptor DESCRIPTOR = new Descriptor();

    @Getter
    private final String configName;

    @DataBoundConstructor
    public ConfigGlobal(final String configName) {
        this.configName = configName;
    }

    @Symbol("ConfigGlobal")
    public static class Descriptor extends ConfigBaseDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_config_configGlobal();
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
