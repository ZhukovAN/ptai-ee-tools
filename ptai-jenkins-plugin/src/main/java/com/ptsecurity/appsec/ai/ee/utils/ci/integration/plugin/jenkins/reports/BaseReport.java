package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.jvnet.localizer.LocaleProvider;
import org.kohsuke.stapler.QueryParameter;

import java.io.Serializable;
import java.util.List;
import java.util.Locale;

public abstract class BaseReport extends AbstractDescribableImpl<BaseReport> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<BaseReport, BaseReportDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), BaseReport.class);

    /**
     * Method converts list of miscellaneous report defined for a job to
     * {@link com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports}
     * instance. If there were conversion errors like JSON parse fail,
     * an ApiException will be thrown
     * @param reports List of miscellaneous reports defined for a job
     * @return Reports instance that containt all the reports defined for a job
     * @throws GenericException Exception that contains error details
     */
    public static Reports convert(final List<BaseReport> reports) throws GenericException {
        if (null == reports || reports.isEmpty()) return null;
        Reports res = new Reports();
        for (BaseReport r : reports) {
            if (r instanceof Data) {
                Data data = (Data) r;
                Reports.Data item = new Reports.Data();
                item.setFormat(Reports.Data.Format.valueOf(data.getFormat()));
                item.setLocale(Reports.Locale.valueOf(data.getLocale()));
                item.setFileName(data.getFileName());
                if (StringUtils.isNotEmpty(data.getFilter()))
                    item.setFilters(Reports.validateJsonFilter(data.getFilter()));
                res.getData().add(item);
            } else if (r instanceof Report) {
                Report data = (Report) r;
                Reports.Report item = new Reports.Report();
                item.setFormat(Reports.Report.Format.valueOf(data.getFormat()));
                item.setLocale(Reports.Locale.valueOf(data.getLocale()));
                item.setFileName(data.getFileName());
                item.setTemplate(data.getTemplate());
                if (StringUtils.isNotEmpty(data.getFilter()))
                    item.setFilters(Reports.validateJsonFilter(data.getFilter()));
                res.getReport().add(item);
            } else if (r instanceof RawData) {
                RawData data = (RawData) r;
                Reports.RawData item = new Reports.RawData();
                item.setFileName(data.getFileName());
                res.getRaw().add(item);
            } else if (r instanceof Json) {
                Json json = (Json) r;
                res.append(Reports.validateJsonReports(json.getJson()));
            }
        }
        return res;
    }

    public static abstract class BaseReportDescriptor extends Descriptor<BaseReport> {

        public FormValidation doCheckFileName(@QueryParameter("fileName") String fileName) {
            return Validator.doCheckFieldNotEmpty(fileName, Resources.i18n_ast_result_reporting_report_file_message_empty());
        }

        public FormValidation doCheckTemplate(@QueryParameter("template") String template) {
            return Validator.doCheckFieldNotEmpty(template, Resources.i18n_ast_result_reporting_report_template_message_empty());
        }

        public FormValidation doCheckFilter(@QueryParameter("filter") String filter) {
            if (Validator.doCheckFieldNotEmpty(filter))
                return Validator.doCheckFieldJsonIssuesFilter(filter, Resources.i18n_ast_result_reporting_report_filter_message_invalid());
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
    public BaseReport clone() throws CloneNotSupportedException {
        return (BaseReport) super.clone();
    }
}
