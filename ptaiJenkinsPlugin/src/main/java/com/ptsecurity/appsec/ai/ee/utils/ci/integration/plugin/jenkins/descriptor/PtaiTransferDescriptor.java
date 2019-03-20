package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.defaults.PtaiTransferDefaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.PtaiTransfer;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import lombok.Getter;
import org.kohsuke.stapler.QueryParameter;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Extension
public class PtaiTransferDescriptor extends Descriptor<PtaiTransfer> {
    public PtaiTransferDescriptor() {
        super(PtaiTransfer.class);
    }

    @Getter
    PtaiTransferDefaults ptaiTransferDefaults = new PtaiTransferDefaults();

    @Override
    public String getDisplayName() {
        return "PtaiTransferDescriptor"; //Messages.hostconfig_descriptor();
    }

    public FormValidation doCheckIncludes(@QueryParameter final String value) {
        return FormValidation.validateRequired(value);
    }

    public FormValidation doCheckPatternSeparator(@QueryParameter final String value) {
        try {
            Pattern.compile(value);
            return FormValidation.ok();
        } catch (PatternSyntaxException e) {
            return FormValidation.error(e, Messages.validator_regularExpression(e.getLocalizedMessage()));
        }
    }
}
