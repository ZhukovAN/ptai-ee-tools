package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.defaults.TransferDefaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import lombok.Getter;
import org.kohsuke.stapler.QueryParameter;

@Extension
public class TransferDescriptor extends Descriptor<Transfer> {
    public TransferDescriptor() {
        super(Transfer.class);
    }

    @Getter
    TransferDefaults transferDefaults = new TransferDefaults();

    @Override
    public String getDisplayName() {
        return "TransferDescriptor";
    }

    public FormValidation doCheckIncludes(@QueryParameter final String includes) {
        return Validator.doCheckFieldNotEmpty(includes, Messages.validator_check_field_empty());
    }

    public FormValidation doCheckPatternSeparator(@QueryParameter final String value) {
        return Validator.doCheckFieldRegEx(value, Messages.validator_check_regex_invalid());
    }
}
