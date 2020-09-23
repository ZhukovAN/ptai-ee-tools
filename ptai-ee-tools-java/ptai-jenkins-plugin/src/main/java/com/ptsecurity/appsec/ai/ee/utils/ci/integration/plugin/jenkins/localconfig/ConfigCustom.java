package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import hudson.Extension;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class ConfigCustom extends ConfigBase {
    @Getter
    private ServerSettings serverSettings;

    @DataBoundConstructor
    public ConfigCustom(
            final ServerSettings serverSettings) {
        this.serverSettings = serverSettings;
    }

    @Symbol("ConfigCustom")
    @Extension
    public static class Descriptor extends ConfigBaseDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_config_configCustom();
        }
    }
}
