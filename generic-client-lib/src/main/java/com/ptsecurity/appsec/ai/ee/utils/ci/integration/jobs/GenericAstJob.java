package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.EventConsumer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Export;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.AstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.SetupOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.io.File;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.*;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.State.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
@SuperBuilder
@ToString
public abstract class GenericAstJob extends AbstractJob implements EventConsumer {
    /**
     * Flag that defines should we wait for AST job to complete, generate
     * reports, make policy assessment etc. or just send files to PT AI
     * server and start scan
     */
    @Setter
    protected boolean async;

    /**
     * Do we need to force full scan mode instead of incremental
     */
    @Getter
    @Setter
    protected boolean fullScanMode;

    @Getter
    @Setter
    protected String projectName;

    @Builder.Default
    protected UUID projectId = null;

    @Builder.Default
    protected UUID scanResultId = null;

    @Getter
    @Builder.Default
    @ToString.Exclude
    protected AstOperations astOps = null;

    @Getter
    @Builder.Default
    @ToString.Exclude
    protected FileOperations fileOps = null;

    @Getter
    @Builder.Default
    @ToString.Exclude
    protected SetupOperations setupOps = null;

    @Getter
    @Builder.Default
    @ToString.Exclude
    protected ScanBrief scanBrief = null;

    @Builder.Default
    protected List<Base> subJobs = new ArrayList<>();

    public void addSubJob(@NonNull final Base job) {
        job.setOwner(this);
        subJobs.add(job);
    }

    public void clearSubJobs() {
        subJobs.clear();
    }

    /**
     * Method sets up AST job and executes it. Method returns FAILED if:
     * - AST complete, policy assessment failed and "fail-if-failed" is defined
     * - AST complete, minor errors / warnings are thrown and "fail-if-unstable" is defined
     * Method throws an exception if:
     * - there were API exceptions
     * - there were settings errors like JSON problems, project not found etc.
     * - sources zip / upload failed
     * - any of {@link GenericAstJob#subJobs} thrown an exception during validation or execution
     * - minor errors during scan
     * @throws GenericException Error details
     */
    protected void unsafeExecute() throws GenericException {
        client.setEventConsumer(this);
        process(Stage.SETUP);
        // Check if all the reports exist. Throw an exception if there are problems
        // Validate postprocessing tasks
        for (Base job : subJobs)
            job.validate();

        projectId = setupOps.setupProject();
        info("PT AI project ID is " + projectId);

        // Zip sources and upload to server. Throw an exception if there are problems
        process(Stage.ZIP);
        File sources = astOps.createZip();

        process(Stage.UPLOAD);
        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(client);
        genericAstTasks.upload(projectId, sources);

        // Start scan
        process(Stage.ENQUEUED);
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
            astOps.scanCompleteCallback(scanBrief, ScanBriefDetailed.Performance.builder().stages(performance()).build());
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
        astOps.scanCompleteCallback(scanBrief, ScanBriefDetailed.Performance.builder().stages(performance()).build());

        // TODO: Check if partial scan results may be retrieved for failed scans
        if (FAILED == scanBrief.getState())
            throw GenericException.raise(
                    Resources.i18n_ast_result_status_failed_server_label(),
                    new IllegalArgumentException("AST job state " + scanBrief.getState()));

        if (ABORTED == scanBrief.getState()) {
            info(abortedFromCi
                    ? Resources.i18n_ast_result_status_interrupted_ci_label()
                    : Resources.i18n_ast_result_status_interrupted_ptai_label());
            throw GenericException.raise(
                    "AST job was terminated",
                    new InterruptedException());
        }

        // Call postprocessing tasks
        for (Base job : subJobs) {
            if (job instanceof Export && !resultsAvailable) continue;
            job.execute(scanBrief);
        }

        info(Resources.i18n_ast_result_status_success_label());
    }

    public void stop() throws GenericException {
        GenericAstTasks projectTasks = new Factory().genericAstTasks(client);
        call(() -> projectTasks.stop(scanResultId), "PT AI project scan stop failed");
    }

    /**
     * List of stage:timestamp pairs that stores scan stage change times. Some stages
     * like initialization may appear multiple times in this list so we need to call
     * {@link GenericAstJob#performance()} to convert timestamps to stage durations
     * and aggregate by stage
     */
    @Builder.Default
    protected transient List<Pair<Stage, ZonedDateTime>> stages = new ArrayList<>();

    public void process(@NonNull final Object event) {
        log.debug("Processing event: {}", event);
        if (event instanceof com.ptsecurity.appsec.ai.ee.scan.progress.Stage) {
            Stage stage = (Stage) event;
            if (stages.isEmpty() || stages.get(stages.size() - 1).getKey() != stage)
                stages.add(new ImmutablePair<>(stage, ZonedDateTime.now()));
        }
    }

    protected Map<Stage, String> performance() {
        // Need to use LinkedHashMap to preserve stages order
        Map<Stage, Duration> durations = new LinkedHashMap<>();
        // Iterate through scan stage timestamps skipping very first
        for (int i = 0 ; i < stages.size() - 1 ; i++) {
            Duration duration = Duration.between(stages.get(i).getValue(), stages.get(i + 1).getValue());
            if (durations.containsKey(stages.get(i).getKey()))
                duration = duration.plus(durations.get(stages.get(i).getKey()));
            durations.put(stages.get(i).getKey(), duration);
        }
        Map<Stage, String> performance = new LinkedHashMap<>();
        for (Map.Entry<Stage, Duration> entry : durations.entrySet())
            performance.put(entry.getKey(), entry.getValue().toString());
        return performance;
    }

    @Override
    protected void validate() throws GenericException {
        super.validate();
    }
}
