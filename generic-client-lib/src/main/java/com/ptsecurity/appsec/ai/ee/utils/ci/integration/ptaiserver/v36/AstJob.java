package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.ApiHelper;
import com.ptsecurity.appsec.ai.ee.ptai.server.api.v36.Converter;
import com.ptsecurity.appsec.ai.ee.ptai.server.api.v36.IssuesModelJsonHelper;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.scanscheduler.model.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.scanscheduler.model.StartScanModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
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
import java.io.FileInputStream;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.scanresult.ScanResult.State.*;
import static com.ptsecurity.appsec.ai.ee.utils.json.Policy.PolicyState.*;

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

    @Setter
    protected String jsonSettings;

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
    protected boolean fullScanMode;

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
        StartScanModel startScanModel = new StartScanModel();
        UUID id = searchProject();
        if (null == id)
            throw ApiException.raise("PT AI project scan start failed", new IllegalArgumentException("PT AI project " + name + " not found"));
        startScanModel.setProjectId(id);
        // Setup scan mode: full or incremental. Default mode is
        // incremental but it can be overridden by JSON settings or forced from UI
        ScanType scanType = ScanType.INCREMENTAL;
        if (null != settings && !settings.isUseIncrementalScan())
            scanType = ScanType.FULL;
        if (fullScanMode)
            scanType = ScanType.FULL;
        startScanModel.setScanType(scanType);
        scanResultId = ApiHelper.callApi(
                () -> scanApi.apiScanStartPost(startScanModel),
                "PT AI project scan start failed");

        info("Scan enqueued, PT AI AST result ID is " + scanResultId);
        astOps.scanStartedCallback(this, scanResultId);

        // Save result URL to artifacts
        final UUID finalProjectId = projectId;
        final String url = ApiHelper.callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdGetCall(finalProjectId, scanResultId, null).request().url().toString(),
                "Failed to get AST result URL");
        ApiHelper.callApi(
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
        waitForComplete(scanResultId);
        ScanResult scanResultV36 = ApiHelper.callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdGet(finalProjectId, scanResultId),
                "Get project scan result failed");
        File issuesModelFile = getJsonResult(finalProjectId, scanResultId);
        IssuesModel issuesModelV36 = Base.callApi(
                () -> IssuesModelJsonHelper.parse(new FileInputStream(issuesModelFile)),
                "Issues model file parse failed");
        Base.callApi(
                issuesModelFile::delete,
                "Temporal file " + issuesModelFile.getPath() + " delete failed", true);
        V36ScanSettings scanSettingsV36 = ApiHelper.callApi(
                () -> projectsApi.apiProjectsProjectIdScanSettingsScanSettingsIdGet(finalProjectId, scanResultV36.getSettingsId()),
                "Get project scan settings failed");
        com.ptsecurity.appsec.ai.ee.scanresult.ScanResult scanResult = Converter.convert(scanResultV36, issuesModelV36, scanSettingsV36);

        // TODO: Move scanCompleteCallback to AstJob and its descendants
        astOps.scanCompleteCallback(this, scanResult);

        com.ptsecurity.appsec.ai.ee.scanresult.ScanResult.State state = scanResult.getState();
        fine("Resulting state is " + state);
        fine("Resulting statistics is " + scanResult.getStatistic());

        if (!EnumSet.of(DONE, ABORTED, FAILED).contains(state))
            throw ApiException.raise(
                    "Unexpected finished scan result state",
                    new IllegalArgumentException(String.valueOf(state)));

        if (FAILED.equals(state)) {
            info(Resources.i18n_ast_result_status_failed_server());
            return JobFinishedStatus.FAILED;
        }

        if (DONE.equals(state) || ABORTED.equals(state))
            // Save user defined reports if scan was started ever
            if (null != reports) generateReports(projectId, scanResultId, reports);

        if (ABORTED.equals(state)) {
            info(Resources.i18n_ast_result_status_interrupted());
            return JobFinishedStatus.INTERRUPTED;
        }

        // Let's process DONE stage warnings / errors and AST policy assessment result
        List<ScanError> errors = getScanErrors(projectId, scanResultId);

        // OK, scan complete, let's check for policy violations
        Policy.PolicyState policyState = Optional.of(scanResult)
                .map(com.ptsecurity.appsec.ai.ee.scanresult.ScanResult::getPolicyState)
                .orElseThrow(() -> ApiException.raise(
                        "PT AI server API error",
                        new NullPointerException("Failed to get finished job policy assessment state")));

        if (REJECTED.equals(policyState)) {
            // AST policy assessment failed
            if (failIfFailed) {
                info(Resources.i18n_ast_result_status_failed_policy());
                return JobFinishedStatus.FAILED;
            }
        } else if (Policy.PolicyState.CONFIRMED.equals(policyState)) {
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

        UUID dummyTemplate = ApiHelper.callApi(() -> Objects.requireNonNull(getDummyReportTemplate(Reports.Locale.EN).getId()), "Dummy report ID is null");
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
                        fine("Processing %s file that is %d bytes long", reportFile.getAbsolutePath(), reportFile.length());
                        fine("Read %s contents to RAM", reportFile);
                        byte[] data = ApiHelper.callApi(
                                () -> Files.readAllBytes(reportFile.toPath()),
                                "Report data read failed");
                        // Method generateReport uses temporal file so we do not need to remove it manually
                        ApiHelper.callApi(
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
                ApiHelper.callApi(
                        () -> fileOps.saveArtifact(raw.getFileName(), json),
                        "Raw JSON result save failed");
            ApiHelper.callApi(
                    json::delete,
                    "Temporal file " + json.getPath() + " delete failed", true);
        }
    }
}
