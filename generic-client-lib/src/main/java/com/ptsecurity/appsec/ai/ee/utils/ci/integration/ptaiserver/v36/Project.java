package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.microsoft.signalr.HubConnection;
import com.ptsecurity.appsec.ai.ee.ptai.server.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.ApiHelper;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.events.ScanCompleteEvent;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.V36ScanSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@SuperBuilder
@ToString(callSuper = true)
public class Project extends Utils {
    @Getter
    @Setter
    protected String name;

    @Setter
    protected File sources;

    public UUID searchProject() throws ApiException {
        return searchProject(name);
    }

    public void upload() throws ApiException {
        UUID id = searchProject();
        if (null == id)
            throw ApiException.raise("PT AI project sources upload failed", new IllegalArgumentException("PT AI project " + name + " not found"));
        callApi(() -> storeApi.uploadSources(id, sources), "PT AI project sources upload failed");
    }

    @SneakyThrows
    public void waitForComplete(@NonNull final UUID scanResultId) throws ApiException {
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

    public List<ScanError> getScanErrors(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws ApiException {
        return ApiHelper.callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdErrorsGet(projectId, scanResultId),
                "PT AI project scan errors read failed");
    }

    public UUID setupFromJson(@NonNull final ScanSettings settings, final Policy[] policy) throws ApiException {
        final V36ScanSettings scanSettings = new V36ScanSettings();
        new V36ScanSettingsHelper().fillV36ScanSettings(scanSettings, settings);

        final UUID projectId;
        ProjectLight projectInfo = ApiHelper.callApi(
                () -> projectsApi.apiProjectsLightNameGet(name),
                "PT AI project search failed");
        if (null == projectInfo) {
            CreateProjectModel createProjectModel = new CreateProjectModel();
            createProjectModel.setName(name);
            createProjectModel.setScanSettings(scanSettings);
            com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Project project = ApiHelper.callApi(
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
