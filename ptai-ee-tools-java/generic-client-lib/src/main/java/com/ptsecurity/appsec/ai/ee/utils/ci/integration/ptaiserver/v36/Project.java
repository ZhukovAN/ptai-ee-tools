package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.microsoft.signalr.HubConnection;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.StartScanModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events.ScanCompleteEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.V36ScanSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.java.Log;

import java.io.File;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;

@Log
public class Project extends Utils {
    @NonNull
    protected final String name;

    @Setter
    protected File sources;

    public Project(@NonNull final String name) {
        super();
        this.name = name;
    }

    public UUID searchProject() throws ApiException {
        return searchProject(name);
    }

    public void upload() throws ApiException {
        UUID id = searchProject();
        if (null == id)
            throw ApiException.raise("PT AI project sources upload failed", new IllegalArgumentException("PT AI project " + name + " not found"));
        callApi(() -> storeApi.uploadSources(id, sources), "PT AI project sources upload failed");
    }

    public UUID scan(@NonNull final String node) throws ApiException {
        StartScanModel startScanModel = new StartScanModel();
        UUID id = searchProject();
        if (null == id)
            throw ApiException.raise("PT AI project scan start failed", new IllegalArgumentException("PT AI project " + name + " not found"));
        startScanModel.setProjectId(id);
        // TODO: Check if there's more intelligent approach required
        startScanModel.setScanType(ScanType.FULL);
        UUID scanResultId = callApi(
                () -> scanApi.apiScanStartPost(startScanModel),
                "PT AI project scan start failed");
        return scanResultId;
    }

    @SneakyThrows
    public ScanResult waitForComplete(@NonNull final UUID scanResultId) throws ApiException {
        // Need this container to save data from lambda
        AtomicReference<ScanResult> res = new AtomicReference<>();

        Semaphore semaphore = new Semaphore(1);
        semaphore.acquire();

        HubConnection connection = createSignalrConnection(scanResultId);

        connection.on("ScanCompleted", (data) -> {
            res.set(data.getResult());
            semaphore.release();
        }, ScanCompleteEvent.class);

        connection.start().blockingAwait();

        semaphore.acquire();
        connection.stop();

        return res.get();
    }

    public ScanResult poll(@NonNull final UUID scanResultId) throws ApiException {
        UUID id = searchProject();
        if (null == id)
            throw ApiException.raise("PT AI project scan status read failed", new IllegalArgumentException("PT AI project " + name + " not found"));
        return poll(id, scanResultId);
    }

    public ScanResult poll(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws ApiException {
        return callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                "PT AI project scan status read failed");
    }

    public void stop(@NonNull final UUID scanResultId) throws ApiException {
        callApi(
                () -> scanApi.apiScanStopPost(scanResultId),
                "PT AI project scan stop failed");
    }

    public File getJsonResult(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws ApiException {
        return callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectId, scanResultId, null),
                "PT AI project scan status JSON read failed");
    }

    public List<ScanError> getScanErrors(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws ApiException {
        return callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdErrorsGet(projectId, scanResultId),
                "PT AI project scan errors read failed");
    }

    public UUID setupFromJson(@NonNull final ScanSettings settings, final Policy[] policy) throws ApiException {
        final V36ScanSettings scanSettings = new V36ScanSettings();
        new V36ScanSettingsHelper().fillV36ScanSettings(scanSettings, settings);

        final UUID projectId;
        ProjectLight projectInfo = callApi(
                () -> projectsApi.apiProjectsLightNameGet(name),
                "PT AI project search failed");
        if (null == projectInfo) {
            CreateProjectModel createProjectModel = new CreateProjectModel();
            createProjectModel.setName(name);
            createProjectModel.setScanSettings(scanSettings);
            com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Project project = callApi(
                    () -> projectsApi.apiProjectsPost(createProjectModel),
                    "PT AI project create failed");
            projectId = project.getId();
        } else {
            projectId = projectInfo.getId();
            callApi(
                    () -> projectsApi.apiProjectsProjectIdScanSettingsPut(projectId, scanSettings),
                    "PT AI project settings update failed");
        }
        if (null == policy) return projectId;
        String policyJson = JsonPolicyHelper.serialize(policy);
        callApi(
                () -> projectsApi.apiProjectsProjectIdPoliciesRulesPut(projectId, policyJson),
                "PT AI project policy update failed");
        return projectId;
    }
}
