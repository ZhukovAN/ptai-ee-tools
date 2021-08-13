package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
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
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.State.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.Policy.PolicyState.REJECTED;
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

    @Getter
    @Builder.Default
    protected boolean reportsGenerated = false;

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
        // Check if all the reports exist. Throw an exception if there are problems
        ReportsTasks reportsTasks = new Factory().reportsTasks(client);
        if (null != reports) {
            reports = reports.validate();
            reportsTasks.check(reports);
        }

        projectId = setupOps.setupProject();
        info("PT AI project ID is " + projectId);

        // Zip sources and upload to server. Throw an exception if there are problems
        File sources = astOps.createZip();
        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
        genericAstTasks.upload(projectId, sources);

        // Start scan
        scanResultId = genericAstTasks.startScan(projectId, fullScanMode);
        info("Scan enqueued, PT AI AST result ID is " + scanResultId);

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
            // completion. Just write scan result access URL and exit
            info(Resources.i18n_ast_result_status_success());
            return;
        }

        // Wait for AST to complete and process results
        // On this line execution we may get:
        // DONE / FAILED if AST job finished
        // ABORTED_FROM_PTAI - AST job was terminated by PT AI viewer
        // InterruptedException - job was terminated from JVM side, i.e. from CI. This case is to be processed individually: we not only need
        ScanBrief.State state = genericAstTasks.waitForComplete(projectId, scanResultId);
        fine("Resulting state is " + state);
        // Scan may be stopped from PT AI Viewer. In this case no scan results will be
        // available even if scan is aborted at the very latest scan stages and some
        // vulnerabilities are found already
        // So we need to check if scan results exist
        try {
            scanBrief = genericAstTasks.getScanBrief(projectId, scanResultId);
            log.debug("Scan brief for project / scan ID {} / {} loaded successfully", projectId, scanResultId);
            fine("Resulting statistics is " + scanBrief.getStatistic());
        } catch (GenericException e) {
            scanBrief = null;
            log.debug("No scan brief exists for project / scan ID {} / {}", projectId, scanResultId);
        }
        astOps.scanCompleteCallback(scanBrief);


        if (!EnumSet.of(DONE, ABORTED_FROM_CI, ABORTED_FROM_PTAI, FAILED).contains(state))
            throw GenericException.raise(
                    "Unexpected finished scan result state",
                    new IllegalArgumentException(String.valueOf(state)));

        if (FAILED.equals(state)) {
            info(Resources.i18n_ast_result_status_failed_server());
            throw GenericException.raise(
                    "AST job failed due to PT AI server error",
                    new IllegalArgumentException(String.valueOf(state)));
        }

        if (ABORTED_FROM_CI.equals(state)) stop();

        if (DONE.equals(state) || ABORTED_FROM_CI.equals(state) || ABORTED_FROM_PTAI.equals(state)) {
            // Save user defined reports if scan was started ever and scan results exist
            if (null != scanBrief && null != reports) reportsTasks.generate(projectId, scanResultId, reports, fileOps);
            reportsGenerated = true;
        }

        if (ABORTED_FROM_PTAI.equals(state) || ABORTED_FROM_CI.equals(state)) {
            info(ABORTED_FROM_CI == state
                    ? Resources.i18n_ast_result_status_interrupted_ci()
                    : Resources.i18n_ast_result_status_interrupted_ptai());
            throw GenericException.raise(
                    "AST job was terminated",
                    new InterruptedException());
        }

        if (null == scanBrief)
            // As the only valid state here is DONE, the scan results are to exist
            throw GenericException.raise(
                    "AST job was done, but brief scan results are not exist",
                    new IllegalArgumentException());

        // Let's process DONE stage warnings / errors and AST policy assessment result
        List<Error> errors = genericAstTasks.getScanErrors(projectId, scanResultId);

        // OK, scan complete, let's check for policy violations
        Policy.PolicyState policyState = Optional.of(scanBrief)
                .map(ScanBrief::getPolicyState)
                .orElseThrow(() -> GenericException.raise(
                        "PT AI server API error",
                        new NullPointerException("Failed to get finished job policy assessment state")));

        if (REJECTED.equals(policyState)) {
            // AST policy assessment failed
            if (failIfFailed) {
                info(Resources.i18n_ast_result_status_failed_policy());
                throw GenericException.raise(
                        "AST policy assessment failed",
                        new AstPolicyViolationException());
            }
        } else if (Policy.PolicyState.CONFIRMED.equals(policyState)) {
            // AST policy assessment OK, check errors / warnings
            if (failIfUnstable && !errors.isEmpty()) {
                info(Resources.i18n_ast_result_status_failed_unstable());
                throw GenericException.raise(
                        "AST failed due to minor errors / warnings during scan",
                        new MinorAstErrorsException());
            }
        } else {
            // No AST policy defined. AST success depends on minor errors / warnings
            if (failIfUnstable && !errors.isEmpty()) {
                info(Resources.i18n_ast_result_status_failed_unstable());
                throw GenericException.raise(
                        "AST failed due to minor errors / warnings during scan",
                        new MinorAstErrorsException());
            }
        }
        info(Resources.i18n_ast_result_status_success());
    }

    public void stop() throws GenericException {
        GenericAstTasks projectTasks = new Factory().genericAstTasks(client);
        call(() -> projectTasks.stop(scanResultId), "PT AI project scan stop failed");
        // If stop was called because of job interruption from CI side then try to generate reports
        if (null == reports) return;
        // If reports are generated already - just exit
        if (reportsGenerated) return;
        // Try to get terminated job results
        try {
            log.debug("Trying to get incomplete AST job brief scan result");
            scanBrief = projectTasks.getScanBrief(projectId, scanResultId);
            if (null == scanBrief) {
                log.debug("Empty scan results for project / results {} / {}, no reports will be generated", projectId, scanResultId);
                return;
            }
            log.debug("Incomplete scan AST job brief scan result loaded");
            ReportsTasks reportsTasks = new Factory().reportsTasks(client);
            reportsTasks.generate(projectId, scanResultId, reports, fileOps);
            log.debug("AST job brief scan result reports generated");
            reportsGenerated = true;
        } catch (GenericException e) {
            log.debug("Failed to get scan results for project / results {} / {}, no reports will be generated", projectId, scanResultId);
            log.trace("Exception details", e);
        }
    }

    public void process(@NonNull final Object event) {

    }
}
