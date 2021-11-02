package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.Getter;
import lombok.NonNull;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.Serializable;

public class Config extends AbstractDescribableImpl<Config> implements Cloneable, Serializable {
    @Getter
    protected final String configName;

    @Getter
    private final ServerSettings serverSettings;

    @DataBoundConstructor
    public Config(
            final String configName,
            final ServerSettings serverSettings) {
        this.configName = configName;
        this.serverSettings = serverSettings;
    }

    @Override
    public Config clone() {
        try {
            return (Config) super.clone();
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    public ConfigDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(ConfigDescriptor.class);
    }

    @Extension
    @Symbol("config")
    public static class ConfigDescriptor extends Descriptor<Config> {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_config_global_label();
        }

        public FormValidation doCheckConfigName(@QueryParameter("configName") String configName) {
            return Validator.doCheckFieldNotEmpty(configName, Resources.i18n_ast_settings_config_global_name_message_empty());
        }
    }
}
