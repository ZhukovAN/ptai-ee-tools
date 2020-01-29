package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

@EqualsAndHashCode
@ToString
public class LegacyConfig extends BaseConfig {
    @Getter
    private LegacyServerSettings legacyServerSettings;

    @DataBoundConstructor
    public LegacyConfig(
            final String configName,
            final LegacyServerSettings legacyServerSettings) {
        this.configName = configName;
        this.legacyServerSettings = legacyServerSettings;
    }

    public LegacyConfigDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(LegacyConfigDescriptor.class);
    }

    @Extension
    public static class LegacyConfigDescriptor extends Descriptor<BaseConfig> {
        public FormValidation doCheckConfigName(@QueryParameter("configName") String configName) {
            return Validator.doCheckFieldNotEmpty(configName, Messages.validator_check_field_empty());
        }

        @Override public String getDisplayName() {
            return Messages.captions_config_legacy_displayName();
        }
    }
}
