package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config.Config;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.Item;
import hudson.util.FormValidation;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

public class ScanSettingsUi extends ScanSettings {
    @Extension
    public static final ScanSettingsDescriptor DESCRIPTOR = new ScanSettingsUiDescriptor();

    @Getter
    private final String projectName;

    @DataBoundConstructor
    public ScanSettingsUi(final String projectName) {
        this.projectName = projectName;
    }

    @Symbol("ScanSettingsUi")
    public static class ScanSettingsUiDescriptor extends ScanSettingsDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_scansettingsui_displayname();
        }

        public FormValidation doCheckProjectName(@QueryParameter("projectName") String projectName) {
            return Validator.doCheckFieldNotEmpty(projectName, Messages.validator_check_field_empty());
        }

        public FormValidation doTestProject(
                @QueryParameter("projectName") final String projectName) {
            return FormValidation.ok();
        }
    }
}
