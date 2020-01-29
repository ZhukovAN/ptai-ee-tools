package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import hudson.Extension;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class ConfigLegacyCustom extends ConfigBase {
    @Getter
    private LegacyServerSettings legacyServerSettings;

    @DataBoundConstructor
    public ConfigLegacyCustom(
            final LegacyServerSettings legacyServerSettings) {
        this.legacyServerSettings = legacyServerSettings;
    }

    @Symbol("ConfigLegacyCustom")
    @Extension
    public static class Descriptor extends ConfigBaseDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_config_configLegacyCustom();
        }
    }
}
