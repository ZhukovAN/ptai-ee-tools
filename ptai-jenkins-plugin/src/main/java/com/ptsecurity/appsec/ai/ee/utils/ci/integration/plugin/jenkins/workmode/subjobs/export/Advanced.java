package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import hudson.Extension;
import hudson.util.FormValidation;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

@ToString
public class Advanced extends Export {
    @Getter
    private final String json;

    @DataBoundConstructor
    public Advanced(final String json) {
        this.json = json;
    }

    @Override
    public void apply(@NonNull JenkinsAstJob job) {
        String json = job.replaceMacro(this.json);
        Reports reports = ReportUtils.validateJsonReports(json);
        new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Advanced(reports).attach(job);
    }

    @Extension
    @Symbol("advanced")
    public static class AdvancedDescriptor extends ExportDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_subjob_export_advanced_label();
        }

        public FormValidation doCheckJson(@QueryParameter String value) {
            FormValidation res = Validator.doCheckFieldNotEmpty(value, Resources.i18n_ast_settings_mode_synchronous_subjob_export_advanced_settings_message_empty());
            if (FormValidation.Kind.ERROR == res.kind) return res;
            return Validator.doCheckFieldJsonReports(value, Resources.i18n_ast_settings_mode_synchronous_subjob_export_advanced_settings_message_invalid());
        }
    }
}
