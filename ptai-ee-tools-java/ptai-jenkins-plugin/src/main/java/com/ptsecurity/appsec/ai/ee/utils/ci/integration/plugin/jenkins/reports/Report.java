package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportFormatType;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;
import java.util.Arrays;

@EqualsAndHashCode
@ToString
public class Report implements Describable<Report>, Serializable {
    @Getter
    private final String template;

    @Getter
    private final String format;

    @Getter
    private final String locale;

    @DataBoundConstructor
    public Report(@NonNull final String template, @NonNull final String format, @NonNull final String locale) {
        this.template = template;
        this.format = format;
        this.locale = locale;
    }

    public ReportDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(ReportDescriptor.class);
    }

    @Extension
    @Symbol("report")
    public static class ReportDescriptor extends Descriptor<Report> {
        public ReportDescriptor() {
            super(Report.class);
        }

        public ListBoxModel doFillFormatItems() {
            ListBoxModel model = new ListBoxModel();
            Arrays.stream(ReportFormatType.values())
                    .filter(t -> !t.equals(ReportFormatType.CUSTOM))
                    .filter(t -> !t.equals(ReportFormatType.PDF))
                    .forEach(t -> model.add(t.getValue()));
            return model;
        }

        public ListBoxModel doFillLocaleItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Messages.captions_locale_english_displayName(), "en-US");
            model.add(Messages.captions_locale_russian_displayName(), "ru-RU");
            return model;
        }
    }
}
