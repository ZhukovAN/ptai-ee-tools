package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.util.FormValidation;
import org.jvnet.localizer.LocaleProvider;
import org.kohsuke.stapler.QueryParameter;

import java.util.Locale;

public abstract class Export extends Base {
    public static abstract class ExportDescriptor extends BaseDescriptor {
        @SuppressWarnings("unused")
        public FormValidation doCheckFileName(@QueryParameter("fileName") String fileName) {
            return Validator.doCheckFieldNotEmpty(fileName, Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_file_message_empty());
        }
        @SuppressWarnings("unused")
        public FormValidation doCheckTemplate(@QueryParameter("template") String template) {
            return Validator.doCheckFieldNotEmpty(template, Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_template_message_empty());
        }
        @SuppressWarnings("unused")
        public FormValidation doCheckFilter(@QueryParameter("filter") String filter) {
            if (Validator.doCheckFieldNotEmpty(filter))
                return Validator.doCheckFieldJsonIssuesFilter(filter, Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_filter_message_invalid());
            else
                return FormValidation.ok();
        }

        public static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale getDefaultLocale() {
            Locale locale = LocaleProvider.getLocale();
            if (locale.getLanguage().equalsIgnoreCase(Reports.Locale.RU.name()))
                return Reports.Locale.RU;
            else
                return Reports.Locale.EN;
        }
    }

    @Override
    public Export clone() throws CloneNotSupportedException {
        return (Export) super.clone();
    }
}
