package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.util.FormValidation;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

@ToString
public class ScanSettingsUi extends ScanSettings {
    @Getter
    private final String projectName;

    @DataBoundConstructor
    public ScanSettingsUi(final String projectName) {
        this.projectName = projectName;
    }

    @Extension
    @Symbol("scanSettingsUi")
    public static class Descriptor extends ScanSettingsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_type_ui_label();
        }

        public FormValidation doCheckProjectName(@QueryParameter("projectName") String projectName) {
            return Validator.doCheckFieldNotEmpty(projectName, Resources.i18n_ast_settings_type_ui_project_message_empty());
        }

        public FormValidation doTestProject(
                @QueryParameter("projectName") final String projectName) {
            return FormValidation.ok();
        }
    }
}
