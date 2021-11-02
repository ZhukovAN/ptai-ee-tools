package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Data;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.RawData;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import lombok.NonNull;

import java.io.File;
import java.util.List;
import java.util.UUID;

public interface ReportsTasks {
    void check(@NonNull final Reports reports);

    void check(@NonNull final Report report) throws GenericException;
    void check(@NonNull final Data data) throws GenericException;
    void check(@NonNull final RawData rawData) throws GenericException;

    /**
     * Generate reports for specific AST result. As this method may be called both
     * for AST job and for CLI reports generation we need to explicitly check reports
     * and not to imply that such check will be done as a first step in
     * calling {@link GenericAstJob#execute()}} method
     * @param projectId PT AI project ID
     * @param scanResultId PT AI AST result ID
     * @param reports Reports to be generated. These reports are explicitly checked
     *                as this method may be called directly as not the part
     *                of {@link GenericAstJob#execute()} call
     * @throws GenericException Exception that contains details about failed report validation / generation
     */
    void generate(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Reports reports, @NonNull final FileOperations fileOps) throws GenericException;

    void generate(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Report report, @NonNull final FileOperations fileOps) throws GenericException;
    void generate(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Data data, @NonNull final FileOperations fileOps) throws GenericException;
    void generate(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final RawData rawData, @NonNull final FileOperations fileOps) throws GenericException;

    UUID getDummyReportTemplateId(@NonNull final Locale locale) throws GenericException;

    File generateReport(
            @NonNull final UUID projectId, @NonNull final UUID scanResultId,
            @NonNull final UUID templateId, @NonNull final Locale locale,
            @NonNull final Report.Format type,
            final Reports.IssuesFilter filters) throws GenericException;

    File generateReport(
            @NonNull final UUID projectId, @NonNull final UUID scanResultId,
            @NonNull final UUID templateId, @NonNull final Locale locale,
            @NonNull final Data.Format type,
            final Reports.IssuesFilter filters) throws GenericException;

    List<String> listReportTemplates(Locale locale) throws GenericException;
}
