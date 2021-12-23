package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import hudson.Extension;
import hudson.util.ListBoxModel;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Arrays;

@ToString
public class JsonXml extends Export {
    @Getter
    private final String locale;

    @Getter
    private final String format;

    @Getter
    private final String fileName;

    @Getter
    private final String filter;

    @Getter
    protected boolean includeDfd;

    @Getter
    protected boolean includeGlossary;

    @DataBoundConstructor
    public JsonXml(final String format, final String fileName,
                   final String locale, final String filter,
                   final boolean includeDfd, final boolean includeGlossary) {
        this.locale = locale;
        this.format = format;
        this.fileName = fileName;
        this.filter = filter;
        this.includeDfd = includeDfd;
        this.includeGlossary = includeGlossary;
    }

    @Override
    public void apply(@NonNull JenkinsAstJob job) {
        String fileName = job.replaceMacro(this.fileName);
        String filter = job.replaceMacro(this.filter);
        Reports.Data data = Reports.Data.builder()
                .locale(Reports.Locale.valueOf(locale))
                .format(Reports.Data.Format.valueOf(format))
                .fileName(fileName)
                .includeDfd(includeDfd)
                .includeGlossary(includeGlossary)
                .filters(StringUtils.isNotEmpty(filter) ? ReportUtils.validateJsonFilter(filter) : null)
                .build();
        new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.JsonXml(data).attach(job);
    }

    @Extension
    @Symbol("jsonXml")
    public static class JsonXmlDescriptor extends ExportDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_subjob_export_jsonxml_label();
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillFormatItems() {
            ListBoxModel model = new ListBoxModel();
            Arrays.stream(Reports.Data.Format.values())
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
        public Reports.Data.Format getDefaultFormat() {
            return Reports.Data.Format.JSON;
        }
    }
}
