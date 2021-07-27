package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import hudson.Extension;
import hudson.model.Item;
import hudson.util.FormValidation;
import lombok.Getter;
import lombok.NonNull;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

public class ScanSettingsManual extends com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettings {
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
    public static class Descriptor extends ScanSettingsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.captions_scanSettingsManual_displayName();
        }

        public FormValidation doCheckJsonSettings(@QueryParameter("jsonSettings") String jsonSettings) {
            FormValidation res = Validator.doCheckFieldNotEmpty(jsonSettings, Messages.validator_check_field_empty());
            if (FormValidation.Kind.OK != res.kind) return res;
            return Validator.doCheckFieldJsonSettings(jsonSettings, Messages.validator_check_jsonSettings_invalid());
        }

        public FormValidation doCheckJsonPolicy(@QueryParameter("jsonPolicy") String jsonPolicy) {
            if (Validator.doCheckFieldNotEmpty(jsonPolicy))
                return Validator.doCheckFieldJsonPolicy(jsonPolicy, Messages.validator_check_jsonPolicy_invalid());
            else
                return FormValidation.ok();
        }

        public FormValidation doTestJsonSettings(
                @AncestorInPath Item item,
                @QueryParameter("jsonSettings") final String jsonSettings) {
            try {
                if (!Validator.doCheckFieldNotEmpty(jsonSettings))
                    return Validator.error(Messages.validator_check_jsonSettings_empty());

                AiProjScanSettings settings = JsonSettingsHelper.verify(jsonSettings);
                return FormValidation.ok(Messages.validator_check_jsonSettings_success(settings.getProjectName(), settings.getProgrammingLanguage()));
            } catch (Exception e) {
                return Validator.error(e);
            }
        }

        public FormValidation doTestJsonPolicy(
                @AncestorInPath Item item,
                @QueryParameter("jsonPolicy") final String jsonPolicy) {
            try {
                if (!Validator.doCheckFieldNotEmpty(jsonPolicy))
                    return FormValidation.ok(Messages.validator_check_jsonPolicy_empty());

                Policy[] policy = JsonPolicyHelper.verify(jsonPolicy);
                if (0 == policy.length)
                    return FormValidation.ok(Messages.validator_check_jsonPolicy_empty());
                else
                    return FormValidation.ok(Messages.validator_check_jsonPolicy_success(policy.length));
            } catch (Exception e) {
                return Validator.error(e);
            }
        }
    }
}
