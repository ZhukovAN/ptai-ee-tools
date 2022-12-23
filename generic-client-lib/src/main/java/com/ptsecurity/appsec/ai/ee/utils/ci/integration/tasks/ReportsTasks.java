package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.*;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import lombok.NonNull;

import java.util.List;
import java.util.UUID;

public interface ReportsTasks {
    void check(@NonNull final Reports reports);

    void check(@NonNull final Report report) throws GenericException;
    void check(@NonNull final RawData rawData) throws GenericException;
    void check(@NonNull final Sarif sarif) throws GenericException;
    void check(@NonNull final SonarGiif sonarGiif) throws GenericException;

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
    void exportAdvanced(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Reports reports, @NonNull final FileOperations fileOps) throws GenericException;

    void exportReport(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Report report, @NonNull final FileOperations fileOps) throws GenericException;

    /**
     * Method saves "raw JSON" issues to file using task-specific file operations
     * @param projectId Project identifier that raw scan results are to be saved as JSON
     * @param scanResultId Scan result identifier that is to be exported as raw JSON
     * @param rawData Raw JSON generation settings like file name etc
     * @param fileOps File operations instance that is used to save results to local file.
     *                Can't just use {@link java.io.File} as this methom may be called remotely
     * @throws GenericException Something bad happened during file export. See {@link GenericException#getCause()} for details
     */
    void exportRawJson(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final RawData rawData, @NonNull final FileOperations fileOps) throws GenericException;

    void exportSarif(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Sarif sarif, @NonNull final FileOperations fileOps) throws GenericException;
    void exportSonarGiif(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final SonarGiif sonarGiif, @NonNull final FileOperations fileOps) throws GenericException;

    List<String> listReportTemplates(Locale locale) throws GenericException;
}
