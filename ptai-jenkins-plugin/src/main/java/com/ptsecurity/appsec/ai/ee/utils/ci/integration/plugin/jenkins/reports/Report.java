package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import hudson.Extension;
import hudson.util.ListBoxModel;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Arrays;

@ToString
public class Report extends BaseReport {
    @Getter
    private final String locale;

    @Getter
    private final String format;

    @Getter
    private final String template;

    @Getter
    private final String fileName;

    @Getter
    private final String filter;

    @DataBoundConstructor
    public Report(final String format, final String template,
                  final String fileName, final String locale,
                  final String filter) {
        this.locale = locale;
        this.format = format;
        this.fileName = fileName;
        this.template = template;
        this.filter = filter;
    }

    @Symbol("Report")
    @Extension
    public static class ReportDescriptor extends BaseReportDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_result_reporting_report_label();
        }

        public ListBoxModel doFillFormatItems() {
            ListBoxModel model = new ListBoxModel();
            Arrays.stream(Reports.Report.Format.values())
                    .forEach(f -> model.add(f.name(), f.name()));
            return model;
        }

        public ListBoxModel doFillLocaleItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Resources.i18n_misc_enums_locale_english_label(), Reports.Locale.EN.name());
            model.add(Resources.i18n_misc_enums_locale_russian_label(), Reports.Locale.RU.name());
            return model;
        }

        public String getDefaultTemplate() {
            return Reports.Locale.RU.name().equals(getDefaultLocale())
                    ? "Отчет по результатам сканирования"
                    : "Scan results report";
        }
    }
}
