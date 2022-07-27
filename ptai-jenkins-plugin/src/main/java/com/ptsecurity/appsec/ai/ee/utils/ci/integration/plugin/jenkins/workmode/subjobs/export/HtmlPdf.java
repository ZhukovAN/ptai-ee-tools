package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import hudson.Extension;
import hudson.util.ListBoxModel;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Arrays;

@ToString
public class HtmlPdf extends Export {
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

    @Getter
    protected boolean includeDfd;

    @Getter
    protected boolean includeGlossary;

    @DataBoundConstructor
    public HtmlPdf(final String format, final String template,
                   final String fileName, final String locale,
                   final String filter,
                   final boolean includeDfd, final boolean includeGlossary) {
        this.locale = locale;
        this.format = format;
        this.fileName = fileName;
        this.template = template;
        this.filter = filter;
        this.includeDfd = includeDfd;
        this.includeGlossary = includeGlossary;
    }

    @Override
    public void apply(@NonNull JenkinsAstJob job) {
        String fileName = job.replaceMacro(this.fileName);
        String template = job.replaceMacro(this.template);
        String filter = job.replaceMacro(this.filter);
        Reports.Report report = Reports.Report.builder()
                .locale(Reports.Locale.valueOf(locale))
                .format(Reports.Report.Format.valueOf(format))
                .fileName(fileName)
                .template(template)
                .includeDfd(includeDfd)
                .includeGlossary(includeGlossary)
                .filters(StringUtils.isNotEmpty(filter) ? ReportUtils.validateJsonFilter(filter) : null)
                .build();
        new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.HtmlPdf(report).attach(job);
    }

    @Extension
    @Symbol("htmlPdf")
    public static class HtmlPdfDescriptor extends ExportDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_label();
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillFormatItems() {
            ListBoxModel model = new ListBoxModel();
            Arrays.stream(Reports.Report.Format.values())
                    .forEach(f -> model.add(f.name(), f.name()));
            return model;
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillLocaleItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Resources.i18n_misc_enums_locale_english_label(), Reports.Locale.EN.name());
            model.add(Resources.i18n_misc_enums_locale_russian_label(), Reports.Locale.RU.name());
            return model;
        }

        @SuppressWarnings("unused")
        public String getDefaultTemplate() {
            return Reports.Locale.RU == getDefaultLocale()
                    ? "Отчет по результатам сканирования"
                    : "Scan results report";
        }

        @SuppressWarnings("unused")
        public Reports.Report.Format getDefaultFormat() {
            return Reports.Report.Format.HTML;
        }
    }
}
