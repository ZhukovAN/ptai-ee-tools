package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.SlimServerSettings;
import hudson.Extension;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class ConfigSlimCustom extends ConfigBase {
    @Getter
    private SlimServerSettings slimServerSettings;

    @DataBoundConstructor
    public ConfigSlimCustom(
            final SlimServerSettings slimServerSettings) {
        this.slimServerSettings = slimServerSettings;
    }

    @Symbol("ConfigSlimCustom")
    @Extension
    public static class Descriptor extends ConfigBaseDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_config_configSlimCustom();
        }
    }
}
