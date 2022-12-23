package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import lombok.Builder;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

import java.util.List;
import java.util.Objects;

@SuperBuilder
public class ListReportTemplatesJob extends AbstractJob {
    @Builder.Default
    protected Reports.Locale locale = Reports.Locale.EN;

    @Getter
    protected List<String> reportTemplates;

    @Override
    protected void init() throws GenericException {

    }

    @Override
    protected void unsafeExecute() throws GenericException {
        ReportsTasks tasks = new Factory().reportsTasks(client);
        reportTemplates = Objects.requireNonNull(tasks.listReportTemplates(locale));
    }
}
