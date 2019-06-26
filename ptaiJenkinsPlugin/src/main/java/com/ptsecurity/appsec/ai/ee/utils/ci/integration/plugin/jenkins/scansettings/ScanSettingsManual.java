package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.util.FormValidation;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

public class ScanSettingsManual extends ScanSettings {
    @Getter
    private final String jsonSettings;

    @Getter
    private final String jsonPolicy;

    @DataBoundConstructor
    public ScanSettingsManual(
            final String jsonSettings, final String jsonPolicy) {
        this.jsonSettings = jsonSettings;
        this.jsonPolicy = jsonPolicy;
    }

    @Symbol("ScanSettingsManual")
    @Extension
    public static class ScanSettingsManualDescriptor extends ScanSettingsDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_scansettingsmanual_displayname();
        }

        public FormValidation doCheckJsonSettings(@QueryParameter("jsonSettings") String jsonSettings) {
            FormValidation res = Validator.doCheckFieldNotEmpty(jsonSettings, Messages.validator_check_field_empty());
            if (FormValidation.Kind.OK != res.kind) return res;
            return Validator.doCheckFieldJsonSettings(jsonSettings, Messages.validator_check_jsonSettings_incorrect());
        }

        public FormValidation doCheckJsonPolicy(@QueryParameter("jsonPolicy") String jsonPolicy) {
            if (Validator.doCheckFieldNotEmpty(jsonPolicy))
                return Validator.doCheckFieldJsonPolicy(jsonPolicy, Messages.validator_check_jsonPolicy_incorrect());
            else
                return FormValidation.ok();
        }
    }
}
