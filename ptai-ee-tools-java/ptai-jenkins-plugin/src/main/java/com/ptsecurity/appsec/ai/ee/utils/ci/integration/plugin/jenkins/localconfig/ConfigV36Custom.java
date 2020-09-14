package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.V36ServerSettings;
import hudson.Extension;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class ConfigV36Custom extends ConfigBase {
    @Getter
    private V36ServerSettings serverSettings;

    @DataBoundConstructor
    public ConfigV36Custom(
            final V36ServerSettings serverSettings) {
        this.serverSettings = serverSettings;
    }

    @Symbol("ConfigV36Custom")
    @Extension
    public static class Descriptor extends ConfigBaseDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_config_configV36Custom();
        }
    }
}
