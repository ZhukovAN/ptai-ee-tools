package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.tasks;

import com.microsoft.signalr.HubConnection;
import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanError;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResultStatistic;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.Stage;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v36.scanscheduler.model.ScanType;
import com.ptsecurity.appsec.ai.ee.server.v36.scanscheduler.model.StartScanModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters.IssuesConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters.ScanErrorsConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.events.ScanCompleteEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters.IssuesConverter.convert;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
public class GenericAstTasksImpl extends AbstractTaskImpl implements GenericAstTasks {
    public GenericAstTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    public void upload(@NonNull final UUID projectId, @NonNull final File sources) throws GenericException {
        call(() -> client.getStoreApi().uploadSources(projectId, sources), "PT AI project sources upload failed");
    }

    @Override
    public UUID startScan(@NonNull UUID projectId, boolean fullScanMode) throws GenericException {
        StartScanModel startScanModel = new StartScanModel();
        startScanModel.setProjectId(projectId);
        // Setup scan mode: full or incremental. Default mode is
        // incremental, but it can be overridden by JSON settings or forced from UI
        ScanType scanType = fullScanMode ? ScanType.FULL : ScanType.INCREMENTAL;
        startScanModel.setScanType(scanType);
        return call(
                () -> client.getScanApi().apiScanStartPost(startScanModel),
                "PT AI project scan start failed");
    }

    @Override
    public String getScanResultUrl(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
        return call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGetCall(projectId, scanResultId, null).request().url().toString(),
                "Failed to get AST result URL");
    }

    @Override
    public ScanBrief.State waitForComplete(@NonNull UUID projectId, @NonNull UUID scanResultId) throws InterruptedException {
        // Semaphore-based implementation was replaced by queue-based as
        // waitForComplete unblocking may be done on several events like
        // ScanCompleted and ScanProgress with aborted and failed stage values
        BlockingQueue<Stage> queue = new LinkedBlockingDeque<>();

        HubConnection connection = client.createSignalrConnection(projectId, scanResultId, queue);
        client.wait(connection, projectId, scanResultId);
        // connection.start().blockingAwait();

        Stage stage = queue.take();
        connection.stop();

        return Stage.FAILED == stage
                ? ScanBrief.State.FAILED
                : Stage.ABORTED == stage
                ? ScanBrief.State.ABORTED
                : Stage.DONE == stage
                ? ScanBrief.State.DONE
                : ScanBrief.State.UNKNOWN;
    }

    public void stop(@NonNull UUID scanResultId) throws GenericException {
        log.debug("Calling scan stop for scan result ID {}", scanResultId);
        // TODO: Implement different approach to stop task that is enqueued but not
        //  started yet. PT AI 3.6 doesn't stop these jobs, so we need to delete scan
        //  result as PT AI viewer does
        call(
                () -> client.getScanApi().apiScanStopPost(scanResultId),
                "PT AI project scan stop failed");
    }

    @NonNull
    @Override
    public ScanBrief createScanBrief(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException {
        String projectName = new ProjectTasksImpl(client).searchProject(projectId);
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                "Get project scan result failed");
        log.debug("Project {} scan result {} load complete", projectId, scanResultId);

        V36ScanSettings scanSettings = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectId, scanResult.getSettingsId()),
                "Get project scan settings failed");
        log.debug("Project {} scan result {} settings loaded", projectId, scanResultId);

        ServerVersionTasks serverVersionTasks = new ServerVersionTasksImpl(client);
        Map<ServerVersionTasks.Component, String> versions = call(serverVersionTasks::current, "PT AI server API version read ailed");

        return ScanBrief.builder()
                .ptaiServerUrl(client.getConnectionSettings().getUrl())
                .ptaiServerVersion(versions.get(ServerVersionTasks.Component.AIE))
                .ptaiAgentVersion(versions.get(ServerVersionTasks.Component.AIC))
                .id(scanResultId)
                .projectId(projectId)
                .projectName(projectName)
                .scanSettings(convert(scanSettings))
                .build();
    }

    /**
     * Adds finished scan execution statistics to scan brief
     * @param scanBrief Scan brief where statistics is to be added to
     * @throws GenericException
     */
    @Override
    public void appendStatistics(@NonNull final ScanBrief scanBrief) throws GenericException {
        log.trace("Getting project {} scan results {}", scanBrief.getProjectId(), scanBrief.getId());
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(scanBrief.getProjectId(), scanBrief.getId()),
                "Get project scan result failed");
        log.debug("Project {} scan result {} load complete", scanBrief.getProjectId(), scanBrief.getId());

        log.trace("Getting scan result statistics");
        ScanResultStatistic statistic = call(
                () -> Objects.requireNonNull(scanResult.getStatistic(), "Scan result statistics is null"),
                "Get scan result statistics failed");
        log.trace("Converting v.3.6 scan result statistics to version-independent data");
        call(
                () -> scanBrief.setStatistics(convert(statistic, scanResult)),
                "Scan result statistics conversion failed");
        log.trace("Setting scan brief policy assessment state");
        call(
                () -> scanBrief.setPolicyState(IssuesConverter.convert(Objects.requireNonNull(statistic.getPolicyState(), "Scan result policy state is null"))),
                "Scan result policy state stage conversion failed");
    }

    @Override
    public ScanBrief getScanBrief(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
        String projectName = new ProjectTasksImpl(client).searchProject(projectId);
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                "Get project scan result failed");
        log.debug("Project {} scan result {} load complete", projectId, scanResultId);

        V36ScanSettings scanSettings = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectId, scanResult.getSettingsId()),
                "Get project scan settings failed");
        log.debug("Project {} scan result {} settings loaded", projectId, scanResultId);

        ServerVersionTasks serverVersionTasks = new ServerVersionTasksImpl(client);
        Map<ServerVersionTasks.Component, String> versions = call(serverVersionTasks::current, "PT AI server API version read ailed");

        com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief res = call(
                () -> convert(projectName, scanResult, scanSettings, client.getConnectionSettings().getUrl(), versions), "Project scan brief convert failed");
        log.debug("Project scan result conversion complete");
        return res;
    }

    @Override
    public ScanResult getScanResult(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                "Get project scan result failed");
        log.debug("Project {} scan result {} load complete", projectId, scanResultId);

        log.trace("Loading issues into temporal files");
        Map<Reports.Locale, File> issuesModelFiles = new HashMap<>();
        Map<Reports.Locale, InputStream> issuesModelStreams = new HashMap<>();
        for (Reports.Locale locale : Reports.Locale.values()) {
            log.trace("Getting issues data using {} locale", locale);
            File issuesModelFile = call(
                    () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectId, scanResultId, locale.getCode()),
                    "PT AI project localized scan status JSON read failed");
            log.debug("Localized ({}) issues stored to temp file {}", locale, issuesModelFile.getAbsolutePath());
            issuesModelFiles.put(locale, issuesModelFile);
            InputStream localizedIssuesModelFileStream = call(
                    () -> new FileInputStream(issuesModelFile),
                    "PT AI project localized scan status temporal file read failed");
            issuesModelStreams.put(locale, localizedIssuesModelFileStream);
        }

        log.trace("Loading project {} scan settings {}", projectId, scanResult.getSettingsId());
        V36ScanSettings scanSettings = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectId, scanResult.getSettingsId()),
                "Get project scan settings failed");
        log.debug("Project {} scan result {} settings loaded", projectId, scanResultId);

        String projectName = call(() -> Objects.requireNonNull(new ProjectTasksImpl(client).searchProject(projectId)), "Project not found");
        ServerVersionTasks serverVersionTasks = new ServerVersionTasksImpl(client);
        Map<ServerVersionTasks.Component, String> versions = call(serverVersionTasks::current, "PT AI server API version read ailed");

        com.ptsecurity.appsec.ai.ee.scan.result.ScanResult res = call(
                () -> convert(projectName, scanResult, issuesModelStreams, scanSettings, client.getConnectionSettings().getUrl(), versions), "Project scan result convert failed");
        log.debug("Project scan result conversion complete");

        log.debug("Starting temporal files deletion");
        for (File issuesModelFile : issuesModelFiles.values()) {
            log.debug("Deleting {}", issuesModelFile.getPath());
            call(
                    issuesModelFile::delete,
                    "Temporal file " + issuesModelFile.getPath() + " delete failed", true);
        }
        return res;
    }

    @Override
    public ScanResult getScanResult(@NonNull ScanBrief scanBrief) throws GenericException {
        ScanResult scanResult = getScanResult(scanBrief.getProjectId(), scanBrief.getId());
        // Scan state may differ between brief and result. This may happen if job was
        // terminated from CI side. In this case we call stop() and load scan results
        // from PT AI server. But if time interval between these two calls is short
        // enough scan result state may stay UNKNOWN
        // So we need to set state from brief
        scanResult.setState(scanBrief.getState());
        return scanResult;
    }

    public List<Error> getScanErrors(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException {
        List<ScanError> errors = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdErrorsGet(projectId, scanResultId),
                "PT AI project scan errors read failed");
        if (null == errors || errors.isEmpty()) return null;
        return errors.stream().map(ScanErrorsConverter::convert).collect(Collectors.toList());
    }
}
