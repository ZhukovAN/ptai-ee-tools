package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.V36ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

public class V36Config extends BaseConfig {
    @Getter
    private V36ServerSettings serverSettings;

    @DataBoundConstructor
    public V36Config(
            final String configName,
            final V36ServerSettings serverSettings) {
        this.configName = configName;
        this.serverSettings = serverSettings;
    }

    public V36ConfigDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(V36ConfigDescriptor.class);
    }

    @Extension
    public static class V36ConfigDescriptor extends Descriptor<BaseConfig> {
        @Override public String getDisplayName() {
            return Messages.captions_config_v36_displayName();
        }
        public FormValidation doCheckConfigName(@QueryParameter("configName") String configName) {
            return Validator.doCheckFieldNotEmpty(configName, Messages.validator_check_field_empty());
        }
    }
}
