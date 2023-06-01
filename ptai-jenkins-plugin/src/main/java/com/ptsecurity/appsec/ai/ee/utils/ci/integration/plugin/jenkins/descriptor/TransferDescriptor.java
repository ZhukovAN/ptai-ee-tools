package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.defaults.TransferDefaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import lombok.Getter;
import lombok.NonNull;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.QueryParameter;

@Extension
@Symbol("transfer")
public class TransferDescriptor extends Descriptor<Transfer> {
    public TransferDescriptor() {
        super(Transfer.class);
    }

    @Getter
    TransferDefaults transferDefaults = new TransferDefaults();

    @Override
    @NonNull
    public String getDisplayName() {
        return "transferDescriptor";
    }

    public FormValidation doCheckIncludes(@QueryParameter final String value) {
        return Validator.doCheckFieldNotEmpty(value, Resources.i18n_ast_settings_transfers_transfer_includes_message_empty());
    }

    public FormValidation doCheckPatternSeparator(@QueryParameter final String value) {
        return Validator.doCheckFieldRegEx(value, Resources.i18n_ast_settings_transfers_transfer_separator_message_invalid());
    }
}
