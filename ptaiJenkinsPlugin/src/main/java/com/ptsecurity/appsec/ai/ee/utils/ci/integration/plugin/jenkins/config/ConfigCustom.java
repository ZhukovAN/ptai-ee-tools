package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ServerSettings;
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
    public static class ConfigCustomDescriptor extends ConfigDescriptor {
        @Override
        public String getDisplayName() {
            return "ConfigCustom";
        }
    }
}
