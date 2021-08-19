package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.AstPolicyViolationException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.MinorAstErrorsException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.EventConsumer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.SetupOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.State.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.Policy.State.REJECTED;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
@SuperBuilder
public abstract class GenericAstJob extends AbstractJob implements EventConsumer {
    /**
     * Flag that defines should we wait for AST job to complete, generate
     * reports, make policy assessment etc. or just send files to PT AI
     * server and start scan
     */
    @Setter
    protected boolean async;

    /**
     * Do we need to throw {@link AstPolicyViolationException} wrapped
     * into {@link GenericException} if AST is done and policy assessment failed
     */
    @Setter
    protected boolean failIfFailed;

    /**
     * Do we need to throw {@link MinorAstErrorsException} wrapped
     * into {@link GenericException} if AST is done and there were minor
     * warnings / errors like missing dependencies etc.
     */
    @Setter
    protected boolean failIfUnstable;

    /**
     * Do we need to force full scan mode instead of incremental
     */
    @Getter
    @Setter
    protected boolean fullScanMode;

    /**
     * Set of reports to be generated
     */
    @Setter
    protected Reports reports;

    @Getter
    @Setter
    protected String projectName;

    @Builder.Default
    protected UUID projectId = null;

    @Builder.Default
    protected UUID scanResultId = null;

    @Builder.Default
    protected AstOperations astOps = null;

    @Builder.Default
    protected FileOperations fileOps = null;

    @Builder.Default
    protected SetupOperations setupOps = null;

    @Getter
    @Builder.Default
    protected ScanBrief scanBrief = null;

    /**
     * Method sets up AST job and executes it. Method returns FAILED if:
     * - AST complete, policy assessment failed and "fail-if-failed" is defined
     * - AST complete, minor errors / warnings are thrown and "fail-if-unstable" is defined
     * Method throws an exception if:
     * - there were API exceptions
     * - there were settings errors like JSON problems, project not found etc.
     * - sources zip / upload failed
     * - {@link GenericAstJob#failIfFailed} is true and policy assessment failed
     * - minor errors during scan
     * @throws GenericException Error details
     */
    protected void unsafeExecute() throws GenericException {
        client.setEventConsumer(this);
        // Check if all the reports exist. Throw an exception if there are problems
        ReportsTasks reportsTasks = new Factory().reportsTasks(client);
        if (null != reports) {
            reports = reports.validate();
            reportsTasks.check(reports);
        }

        projectId = setupOps.setupProject();
        info("PT AI project ID is " + projectId);

        // Zip sources and upload to server. Throw an exception if there are problems
        process(Stage.ZIP);
        File sources = astOps.createZip();
        process(Stage.UPLOAD);
        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
        genericAstTasks.upload(projectId, sources);

        // Start scan
        scanResultId = genericAstTasks.startScan(projectId, fullScanMode);
        info("Scan enqueued, PT AI AST result ID is " + scanResultId);
        // Now we know scan result ID, so create initial scan brief with ID's and scan settings
        scanBrief = genericAstTasks.createScanBrief(projectId, scanResultId);
        scanBrief.setUseAsyncScan(async);

        // Notify descendants about scan started event
        astOps.scanStartedCallback(projectId, scanResultId);

        // Save result URL to artifacts
        final String url = genericAstTasks.getScanResultUrl(projectId, scanResultId);
        log.debug("Save AST result REST API URL {} to file", url);
        call(
                () -> fileOps.saveArtifact("rest.url", url.getBytes()),
                "AST result REST API URL save failed");
        info("AST result REST API URL: " + url);

        if (async) {
            // Asynchronous mode means that we aren't need to wait AST job
            // completion. Just notify descendant and exit
            info(Resources.i18n_ast_result_status_success_label());
            astOps.scanCompleteCallback(scanBrief, performance);
            return;
        }

        // Wait for AST to complete and process results
        // On this line execution we may get:
        // DONE / FAILED if AST job finished
        // ABORTED - AST job was terminated by PT AI viewer
        // InterruptedException - job was terminated from JVM side, i.e. from CI.
        boolean abortedFromCi = false;
        try {
            scanBrief.setState(genericAstTasks.waitForComplete(projectId, scanResultId));
        } catch (InterruptedException e) {
            process(Stage.ABORTED);
            scanBrief.setState(ABORTED);
            abortedFromCi = true;
            stop();
        }
        fine("Resulting state is " + scanBrief.getState());
        if (!EnumSet.of(DONE, ABORTED, FAILED).contains(scanBrief.getState()))
            throw GenericException.raise(
                    "Unexpected finished scan result state",
                    new IllegalArgumentException(String.valueOf(scanBrief.getState())));

        // Scan may be stopped from PT AI Viewer. In this case no scan results will be
        // available even if scan is aborted at the very latest scan stages and some
        // vulnerabilities are found already
        boolean resultsAvailable = true;
        try {
            genericAstTasks.appendStatistics(scanBrief);
            log.debug("Scan brief for project / scan ID {} / {} loaded successfully", projectId, scanResultId);
            fine("Resulting statistics is " + scanBrief.getStatistics());
        } catch (GenericException e) {
            resultsAvailable = false;
            log.debug("Scan brief for project / scan ID {} / {} load failed", projectId, scanResultId);
            log.debug("Exception details", e);
        }
        astOps.scanCompleteCallback(scanBrief, performance);

        // TODO: Check if partial scan results may be retrieved for failed scans
        if (FAILED == scanBrief.getState())
            throw GenericException.raise(
                    Resources.i18n_ast_result_status_failed_server_label(),
                    new IllegalArgumentException("AST job state " + scanBrief.getState().toString()));

        if (resultsAvailable && null != reports) reportsTasks.generate(projectId, scanResultId, reports, fileOps);

        if (ABORTED == scanBrief.getState()) {
            info(abortedFromCi
                    ? Resources.i18n_ast_result_status_interrupted_ci_label()
                    : Resources.i18n_ast_result_status_interrupted_ptai_label());
            throw GenericException.raise(
                    "AST job was terminated",
                    new InterruptedException());
        }

        // Let's process DONE stage warnings / errors and AST policy assessment result
        List<Error> errors = genericAstTasks.getScanErrors(projectId, scanResultId);

        // OK, scan complete, let's check for policy violations
        Policy.State policyState = Optional.of(scanBrief)
                .map(ScanBrief::getPolicyState)
                .orElseThrow(() -> GenericException.raise(
                        "PT AI server API error",
                        new NullPointerException("Failed to get finished job policy assessment state")));

        if (REJECTED.equals(policyState)) {
            // AST policy assessment failed
            if (failIfFailed) {
                info(Resources.i18n_ast_result_status_failed_policy_label());
                throw GenericException.raise(
                        "AST policy assessment failed",
                        new AstPolicyViolationException());
            }
        } else if (Policy.State.CONFIRMED.equals(policyState)) {
            // AST policy assessment OK, check errors / warnings
            if (failIfUnstable && !errors.isEmpty()) {
                info(Resources.i18n_ast_result_status_failed_unstable_label());
                throw GenericException.raise(
                        "AST failed due to minor errors / warnings during scan",
                        new MinorAstErrorsException());
            }
        } else {
            // No AST policy defined. AST success depends on minor errors / warnings
            if (failIfUnstable && !errors.isEmpty()) {
                info(Resources.i18n_ast_result_status_failed_unstable_label());
                throw GenericException.raise(
                        "AST failed due to minor errors / warnings during scan",
                        new MinorAstErrorsException());
            }
        }
        info(Resources.i18n_ast_result_status_success_label());
    }

    public void stop() throws GenericException {
        GenericAstTasks projectTasks = new Factory().genericAstTasks(client);
        call(() -> projectTasks.stop(scanResultId), "PT AI project scan stop failed");
    }

    @Builder.Default
    protected ScanBriefDetailed.Performance performance = ScanBriefDetailed.Performance.builder().build();

    public void process(@NonNull final Object event) {
        log.debug("Processing event: {}", event);
        if (event instanceof com.ptsecurity.appsec.ai.ee.scan.progress.Stage) {
            Stage stage = (Stage) event;
            if (null == scanBrief) return;
            if (!performance.getStages().containsKey(stage))
                performance.getStages().put(stage, ZonedDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
        }
    }
}
