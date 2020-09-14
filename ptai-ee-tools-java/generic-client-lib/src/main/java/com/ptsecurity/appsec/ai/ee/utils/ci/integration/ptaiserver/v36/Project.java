package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ProjectLight;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanResult;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.StartScanModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.exceptions.ApiException;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.java.Log;
import lombok.extern.log4j.Log4j2;

import java.io.File;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;

@Log
@RequiredArgsConstructor
public class Project extends BaseClient {
    protected final String name;

    @Setter
    protected File sources;

    public UUID searchProject() throws ApiException {
        ProjectLight projectLight = callApi(
                () -> projectsApi.apiProjectsLightNameGet(name),
                "PT AI project search failed");
        return (null == projectLight) ? null : projectLight.getId();
    }

    public void upload() throws ApiException {
        UUID id = searchProject();
        if (null == id)
            ApiException.raise("PT AI project not found", new IllegalArgumentException());
        callApi(() -> storeApi.uploadSources(id, sources), "PT AI project sources upload failed");
    }

    public UUID scan(@NonNull final String node) throws ApiException {
        StartScanModel startScanModel = new StartScanModel();
        UUID id = searchProject();
        if (null == id)
            ApiException.raise("PT AI project not found", new IllegalArgumentException());
        startScanModel.setProjectId(id);
        // TODO: Check if there's more intelligent approach required
        startScanModel.setScanType(ScanType.FULL);
        UUID scanResultId = callApi(
                () -> scanApi.apiScanStartPost(startScanModel),
                "PT AI project scan start failed");
        return scanResultId;
    }

    public ScanResult poll(@NonNull final UUID scanResultId) throws ApiException {
        UUID id = searchProject();
        if (null == id)
            ApiException.raise("PT AI project not found", new IllegalArgumentException());
        return poll(id, scanResultId);
    }

    public ScanResult poll(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws ApiException {
        return callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                "PT AI project scan status read failed");
    }

    public void stop(@NonNull final UUID scanResultId) {
        callApi(
                () -> scanApi.apiScanStopPost(scanResultId),
                "PT AI project scan stop failed");
    }

    public File getJsonResult(@NonNull final UUID projectId, @NonNull final UUID scanResultId) {
        return callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectId, scanResultId, null),
                "PT AI project scan status JSON read failed");
    }
}
