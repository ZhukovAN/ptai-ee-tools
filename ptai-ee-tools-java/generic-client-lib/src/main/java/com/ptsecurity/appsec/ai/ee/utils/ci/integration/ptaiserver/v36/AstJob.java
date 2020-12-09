package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.Builder;
import lombok.NonNull;
import lombok.Setter;
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

import static com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Stage.*;

@Slf4j
@SuperBuilder
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

    @Nullable
    @Setter
    protected String node;

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
    private UUID scanResultId = null;

    protected AstOperations astOps;

    protected FileOperations fileOps;

    public JobFinishedStatus execute() {
        try {
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

            // Zip sources and upload to server
            sources = astOps.createZip();
            upload();

            // Start scan
            scanResultId = scan(node);
            info("PT AI AST result ID is " + scanResultId);
            astOps.scanStartedCallback(this, scanResultId);

            // Save result URL to artifacts
            String url = projectsApi.apiProjectsProjectIdScanResultsScanResultIdGetCall(projectId, scanResultId, null).request().url().toString();
            callApi(
                    () -> fileOps.saveArtifact("result.url", url.getBytes()),
                    "AST result URL save failed");

            if (async) {
                // Asynchronous mode means that we aren't need to wait AST job
                // completion. Just write scan result access URL and exit
                info(Messages.i18n_ast_result_success());
                return JobFinishedStatus.SUCCESS;
            }

            // Wait for AST to complete and process results
            ScanResult state = waitForComplete(scanResultId);
            astOps.scanCompleteCallback();

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
                info(Messages.i18n_ast_result_failed_server());
                return JobFinishedStatus.FAILED;
            }

            if (DONE.equals(stage) || ABORTED.equals(stage))
                // Save user defined reports if scan was started ever
                if (null != reports) generateReports(projectId, scanResultId, reports);

            if (ABORTED.equals(stage)) {
                info(Messages.i18n_ast_result_interrupted());
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
                    info(Messages.i18n_ast_result_failed_policy());
                    return JobFinishedStatus.FAILED;
                }
            } else if (PolicyState.REJECTED.equals(policyState)) {
                // AST policy assessment OK, check errors / warnings
                if (failIfUnstable && !errors.isEmpty()) {
                    info(Messages.i18n_ast_result_failed_unstable());
                    return JobFinishedStatus.FAILED;
                }
            } else {
                // No AST policy defined. AST success depends on minor errors / warnings
                if (failIfUnstable && !errors.isEmpty()) {
                    info(Messages.i18n_ast_result_failed_unstable());
                    return JobFinishedStatus.FAILED;
                }
            }
            info(Messages.i18n_ast_result_success());
            return JobFinishedStatus.SUCCESS;
        } catch (ApiException e) {
            severe(e);
            return JobFinishedStatus.FAILED;
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                stop();
                severe(Messages.i18n_ast_result_interrupted());
                return JobFinishedStatus.INTERRUPTED;
            } else {
                severe(ApiException.raise(Messages.i18n_ast_result_failed(), e));
                return JobFinishedStatus.FAILED;
            }
        }
    }

    public void generateReports(@NonNull final UUID projectId, @NonNull final UUID scanResultId, @NonNull final Reports reports) {
        if (null == fileOps)
            throw ApiException.raise("File operations aren't defined", new NullPointerException());

        UUID dummyTemplate = getDummyReportTemplate(Reports.Locale.EN).getId();
        final AtomicReference<UUID> finalProjectId = new AtomicReference<>(projectId);

        Stream.concat(reports.getData().stream(), reports.getReport().stream())
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
        if (null != reports.getRaw()) {
            // Save raw JSON report
            File json = getJsonResult(projectId, scanResultId);
            for (Reports.RawData raw : reports.getRaw())
                callApi(
                        () -> fileOps.saveArtifact(raw.getFileName(), json),
                        "Raw JSON result save failed");
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
}
