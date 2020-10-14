package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportFormatType;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportTemplateModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.BaseConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.Config;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ReportHelper;
import hudson.Extension;
import hudson.RelativePath;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

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

    public String fileNameTemplate() {
        return ReportHelper.generateReportFileNameTemplate(template, locale, format);
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
