package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.GlobalConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;


@Extension
public class GlobalConfigDescriptor extends Descriptor<GlobalConfig> {
    public GlobalConfigDescriptor() {
        super(GlobalConfig.class);
    }

    @Override
    public String getDisplayName() {
        return "PTAI global configuration";
    }

    public FormValidation doCheckConfigName(@QueryParameter("configName") String configName) {
        return Validator.doCheckFieldNotEmpty(configName, Messages.validator_check_field_empty());
    }
}
