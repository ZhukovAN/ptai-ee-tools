package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.annotation.Nullable;
import java.io.File;
import java.nio.file.Files;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Stage.*;

@Slf4j
@Getter
@SuperBuilder
@ToString(callSuper = true)
public abstract class AstJob extends Project {
    /**
     * AST job execution status. Status defined by combination of
     */
    public enum JobFinishedStatus {
        INTERRUPTED, SUCCESS, FAILED
    }

    @Nullable
    @Setter
    protected String jsonSettings;
    @Nullable
    @Setter
    protected String jsonPolicy;

    /**
     * Flag that defines should we wait for AST job to complete, generate
     * reports, make policy assessment etc. or just send files to PT AI
     * server and start scan
     */
    @Setter
    protected boolean async;

    @Setter
    protected boolean failIfFailed;
    @Setter
    protected boolean failIfUnstable;

    @Setter
    protected Reports reports;

    /**
     * Unique ID of scan results for job just started
     */
    @Builder.Default
    @ToString.Exclude
    private UUID scanResultId = null;

    @ToString.Exclude
    protected AstOperations astOps;

    @ToString.Exclude
    protected FileOperations fileOps;

    /**
     * Method sets up AST job and executes it. Method returns FAILED if:
     * - AST complete, policy assessment failed and "fail-if-failed" is defined
     * - AST complete, minor errors / warnings are thrown and "fail-if-unstable" is defined
     * Method throws an exception if:
     * - there were API exceptions
     * - there were settings errors like JSON problems, project not found etc.
     * - sources sip / upload failed
     * @return AST job execution status
     * @throws ApiException Error details
     */
    protected JobFinishedStatus unsafeExecute() throws ApiException {
        // Check if all the reports are exist. Throw an exception if there are problems
        if (null != reports)
            reports = reports.validate().check(this);

        // Check if JSON settings and policy are defined correctly. Throw an exception if there are problems
        ScanSettings settings = (StringUtils.isEmpty(jsonSettings))
                ? null
                : JsonSettingsHelper.verify(jsonSettings);
        Policy[] policy = (StringUtils.isEmpty(jsonPolicy))
                ? null
                : JsonPolicyHelper.verify(jsonPolicy);

        if (null != settings)
            name = settings.getProjectName();

        // If project not exist - JSON settings are to be defined
        UUID projectId = searchProject();
        if (null == projectId) {
            if (null != settings) {
                info("Project %s not found, will be created as JSON settings are defined", name);
                projectId = setupFromJson(settings, policy);
            } else {
                info("Project %s not found", name);
                return JobFinishedStatus.FAILED;
            }
        } else if (null != settings)
            setupFromJson(settings, policy);
        info("PT AI project ID is " + projectId);

        // Zip sources and upload to server. Throw an exception if there are problems
        sources = astOps.createZip();
        upload();

        // Start scan
        scanResultId = scan();
        info("Scan enqueued, PT AI AST result ID is " + scanResultId);
        astOps.scanStartedCallback(this, scanResultId);

        // Save result URL to artifacts
        final UUID finalProjectId = projectId;
        final String url = callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdGetCall(finalProjectId, scanResultId, null).request().url().toString(),
                "Failed to get AST result URL");
        callApi(
                () -> fileOps.saveArtifact("rest.url", url.getBytes()),
                "AST result REST API URL save failed");
        info("AST result REST API URL: " + url);

        if (async) {
            // Asynchronous mode means that we aren't need to wait AST job
            // completion. Just write scan result access URL and exit
            info(Resources.i18n_ast_result_status_success());
            // TODO: Implement special AstResultAction processing for async mode
            return JobFinishedStatus.SUCCESS;
        }

        // Wait for AST to complete and process results
        ScanResult state = waitForComplete(scanResultId);
        // TODO: Move scanCompleteCallback to AstJob and its descendants
        astOps.scanCompleteCallback(this, scanResultId, state);

        Stage stage = Optional.of(state)
                .map(ScanResult::getProgress)
                .map(ScanProgress::getStage)
                .orElseThrow(() -> ApiException.raise(
                        "PT AI server API error",
                        new NullPointerException("Failed to get finished job scan progress")));
        fine("Resulting stage is " + stage);
        fine("Resulting statistics is " + state.getStatistic());

        if (!EnumSet.of(DONE, ABORTED, FAILED).contains(stage))
            throw ApiException.raise(
                    "Unexpected finished scan result stage",
                    new IllegalArgumentException(String.valueOf(stage)));

        if (FAILED.equals(stage)) {
            info(Resources.i18n_ast_result_status_failed_server());
            return JobFinishedStatus.FAILED;
        }

        if (DONE.equals(stage) || ABORTED.equals(stage))
            // Save user defined reports if scan was started ever
            if (null != reports) generateReports(projectId, scanResultId, reports);

        if (ABORTED.equals(stage)) {
            info(Resources.i18n_ast_result_status_interrupted());
            return JobFinishedStatus.INTERRUPTED;
        }

        // Let's process DONE stage warnings / errors and AST policy assessment result
        List<ScanError> errors = getScanErrors(projectId, scanResultId);

        // OK, scan complete, let's check for policy violations
        PolicyState policyState = Optional.of(state)
                .map(ScanResult::getStatistic)
                .map(ScanResultStatistic::getPolicyState)
                .orElseThrow(() -> ApiException.raise(
                        "PT AI server API error",
                        new NullPointerException("Failed to get finished job policy assessment state")));

        // TODO: Swap REJECTED/CONFIRMED states when https://jira.ptsecurity.com/browse/AI-4866 will be fixed
        if (PolicyState.CONFIRMED.equals(policyState)) {
            // AST policy assessment failed
            if (failIfFailed) {
                info(Resources.i18n_ast_result_status_failed_policy());
                return JobFinishedStatus.FAILED;
            }
        } else if (PolicyState.REJECTED.equals(policyState)) {
            // AST policy assessment OK, check errors / warnings
            if (failIfUnstable && !errors.isEmpty()) {
                info(Resources.i18n_ast_result_status_failed_unstable());
                return JobFinishedStatus.FAILED;
            }
        } else {
            // No AST policy defined. AST success depends on minor errors / warnings
            if (failIfUnstable && !errors.isEmpty()) {
                info(Resources.i18n_ast_result_status_failed_unstable());
                return JobFinishedStatus.FAILED;
            }
        }
        info(Resources.i18n_ast_result_status_success());
        return JobFinishedStatus.SUCCESS;
    }

    /**
     * Method sets up AST job and executes it. Method returns FAILED if:
     * - there were API exceptions
     * - there were settings errors like JSON problems, project not found etc.
     * - sources sip / upload failed
     * - AST complete, policy assessment failed and "fail-if-failed" is defined
     * - AST complete, minor errors / warnings are thrown and "fail-if-unstable" is defined
     * If there were errors despite AST started or there were just settings misconfiguration, return FAILED
     * @return AST job execution status
     */
    public JobFinishedStatus execute() {
        try {
            return unsafeExecute();
        } catch (ApiException e) {
            severe(e);
            return JobFinishedStatus.FAILED;
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                // TODO: Check this warning
                stop();
                severe(Resources.i18n_ast_result_status_interrupted());
                return JobFinishedStatus.INTERRUPTED;
            } else {
                severe(ApiException.raise(Resources.i18n_ast_result_status_failed(), e));
                return JobFinishedStatus.FAILED;
            }
        }
    }

    public void stop() {
        if (null == scanResultId) return;
        try {
            this.stop(scanResultId);
        } catch (ApiException e) {
            severe(e);
        }
    }

    /**
     * Generate reports for specific AST result. As this method may be called both
     * for AST job and for CLI reports generation we need to explicitly check reports
     * and not to imply that such check will be done as a first step in
     * calling {@link AstJob#execute()} method
     * @param projectId PT AI project ID
     * @param scanResultId PT AI AST result ID
     * @param reports Reports to be generated. These reports are explicitly checked
     *                as this method may be called directly as not the part
     *                of {@link AstJob#execute()} call
     * @throws ApiException Exception that contains details about failed report validation / generation
     */
    public void generateReports(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Reports reports) throws ApiException {
        if (null == fileOps)
            throw ApiException.raise("File operations aren't defined", new NullPointerException());

        final Reports checkedReports = reports.validate().check(this);

        UUID dummyTemplate = getDummyReportTemplate(Reports.Locale.EN).getId();
        final AtomicReference<UUID> finalProjectId = new AtomicReference<>(projectId);

        Stream.concat(checkedReports.getData().stream(), checkedReports.getReport().stream())
                .forEach(r -> {
                    File reportFile;
                    try {
                        if (r instanceof Reports.Report) {
                            Reports.Report report = (Reports.Report) r;
                            reportFile = generateReport(
                                    finalProjectId.get(), scanResultId,
                                    report.getTemplate(), report.getLocale(),
                                    report.getFormat().getValue(), report.getFilters());
                        } else if (r instanceof Reports.Data) {
                            Reports.Data data = (Reports.Data) r;
                            reportFile = generateReport(
                                    finalProjectId.get(), scanResultId,
                                    dummyTemplate, data.getLocale(),
                                    data.getFormat().getValue(), data.getFilters());
                        } else return;
                        byte[] data = callApi(
                                () -> Files.readAllBytes(reportFile.toPath()),
                                "Report data read failed");
                        // Method generateReport uses temporal file so we do not need to remove it manually
                        callApi(
                                () -> fileOps.saveArtifact(r.getFileName(), data),
                                "Report file save failed");
                    } catch (ApiException e) {
                        warning(e);
                    }
                });
        if (null != checkedReports.getRaw()) {
            // Save raw JSON report
            File json = getJsonResult(projectId, scanResultId);
            for (Reports.RawData raw : checkedReports.getRaw())
                callApi(
                        () -> fileOps.saveArtifact(raw.getFileName(), json),
                        "Raw JSON result save failed");
        }
    }
}
