package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.Getter;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.QueryParameter;

import java.io.Serializable;
import java.util.List;

public abstract class BaseReport extends AbstractDescribableImpl<BaseReport> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<BaseReport, BaseReportDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), BaseReport.class);

    public static Reports validate(final List<BaseReport> reports,
                                   @NonNull final Utils utils) throws ApiException {
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
                    item.setFilters(Reports.verify(data.getFilter()));
                res.getData().add(item);
            } else if (r instanceof Report) {
                Report data = (Report) r;
                Reports.Report item = new Reports.Report();
                item.setFormat(Reports.Report.Format.valueOf(data.getFormat()));
                item.setLocale(Reports.Locale.valueOf(data.getLocale()));
                item.setFileName(data.getFileName());
                item.setTemplate(data.getTemplate());
                if (StringUtils.isNotEmpty(data.getFilter()))
                    item.setFilters(Reports.verify(data.getFilter()));
                res.getReport().add(item);
            } else if (r instanceof RawData) {
                RawData data = (RawData) r;
                Reports.RawData item = new Reports.RawData();
                item.setFileName(data.getFileName());
                res.getRaw().add(item);
            }
        }
        return res.validate(utils).fix();
    }

    public static abstract class BaseReportDescriptor extends Descriptor<BaseReport> {

        public FormValidation doCheckFileName(@QueryParameter("fileName") String fileName) {
            return Validator.doCheckFieldNotEmpty(fileName, Messages.validator_check_field_empty());
        }

        public FormValidation doCheckTemplate(@QueryParameter("template") String template) {
            return Validator.doCheckFieldNotEmpty(template, Messages.validator_check_field_empty());
        }

        public FormValidation doCheckFilter(@QueryParameter("filter") String filter) {
            if (Validator.doCheckFieldNotEmpty(filter))
                return Validator.doCheckFieldJsonIssuesFilter(filter, Messages.i18n_validator_reporting_issuesfilter_incorrect());
            else
                return FormValidation.ok();
        }
    }

    @Override
    public BaseReport clone() throws CloneNotSupportedException {
        return (BaseReport)super.clone();
    }
}
