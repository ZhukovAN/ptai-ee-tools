package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.tasks;

import com.microsoft.signalr.HubConnection;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanError;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v36.scanscheduler.model.ScanType;
import com.ptsecurity.appsec.ai.ee.server.v36.scanscheduler.model.StartScanModel;
import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

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
        // incremental but it can be overridden by JSON settings or forced from UI
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
    public void waitForComplete(@NonNull UUID scanResultId) throws GenericException {
        try {
            // Need this container to save data from lambda
            AtomicReference<com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult> res = new AtomicReference<>();

            Semaphore semaphore = new Semaphore(1);
            semaphore.acquire();

            HubConnection connection = client.createSignalrConnection(scanResultId);

            connection.on("ScanCompleted", (data) -> {
                res.set(data.getResult());
                semaphore.release();
            }, ScanCompleteEvent.class);

            connection.start().blockingAwait();

            semaphore.acquire();
            connection.stop();
        } catch (InterruptedException e) {
            throw GenericException.raise("Job interruted", e);
        }
    }

    public void stop(@NonNull UUID scanResultId) throws GenericException {
        call(
                () -> client.getScanApi().apiScanStopPost(scanResultId),
                "PT AI project scan stop failed");
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
                () -> IssuesConverter.convert(projectName, scanResult, scanSettings, versions), "Project scan brief convert failed");
        log.debug("Project scan result conversion complete");
        return res;
    }

    @Override
    public ScanResult getScanResult(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                "Get project scan result failed");
        log.debug("Project {} scan result {} load complete", projectId, scanResultId);

        File issuesModelFile = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectId, scanResultId, null),
                "PT AI project scan status JSON read failed");
        log.debug("Issues stored to temp file {}", issuesModelFile.getAbsolutePath());

        V36ScanSettings scanSettings = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectId, scanResult.getSettingsId()),
                "Get project scan settings failed");
        log.debug("Project {} scan result {} settings loaded", projectId, scanResultId);

        String projectName = call(() -> Objects.requireNonNull(new ProjectTasksImpl(client).searchProject(projectId)), "Project not found");
        ServerVersionTasks serverVersionTasks = new ServerVersionTasksImpl(client);
        Map<ServerVersionTasks.Component, String> versions = call(serverVersionTasks::current, "PT AI server API version read ailed");

        com.ptsecurity.appsec.ai.ee.scan.result.ScanResult res = call(
                () -> IssuesConverter.convert(projectName, scanResult, new FileInputStream(issuesModelFile), scanSettings, versions), "Project scan result convert failed");
        log.debug("Project scan result conversion complete");
        call(
                issuesModelFile::delete,
                "Temporal file " + issuesModelFile.getPath() + " delete failed", true);
        return res;
    }

    public List<Error> getScanErrors(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException {
        List<ScanError> errors = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdErrorsGet(projectId, scanResultId),
                "PT AI project scan errors read failed");
        if (null == errors || errors.isEmpty()) return null;
        return errors.stream().map(ScanErrorsConverter::convert).collect(Collectors.toList());
    }
}
