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
public class Data extends BaseReport {
    @Getter
    private final String locale;

    @Getter
    private final String format;

    @Getter
    private final String fileName;

    @Getter
    private final String filter;

    @DataBoundConstructor
    public Data(final String format, final String fileName,
                final String locale, final String filter) {
        this.locale = locale;
        this.format = format;
        this.fileName = fileName;
        this.filter = filter;
    }

    @Symbol("data")
    @Extension
    public static class DataDescriptor extends BaseReportDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_result_reporting_data_label();
        }

        public ListBoxModel doFillFormatItems() {
            ListBoxModel model = new ListBoxModel();
            Arrays.stream(Reports.Data.Format.values())
                    .forEach(f -> model.add(f.name(), f.name()));
            return model;
        }

        public ListBoxModel doFillLocaleItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Resources.i18n_misc_enums_locale_english_label(), Reports.Locale.EN.name());
            model.add(Resources.i18n_misc_enums_locale_russian_label(), Reports.Locale.RU.name());
            return model;
        }
    }
}
