package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import hudson.Extension;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class ConfigCustom extends ConfigBase {
    @Getter
    private final ServerSettings serverSettings;

    @DataBoundConstructor
    public ConfigCustom(
            final ServerSettings serverSettings) {
        this.serverSettings = serverSettings;
    }

    @Extension
    @Symbol("configCustom")
    public static class Descriptor extends ConfigBaseDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_config_custom_label();
        }
    }
}
