package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.ServerSettingsDescriptor;
import hudson.Extension;
import hudson.model.Item;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.util.List;

public class ConfigCustom extends Config {
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
