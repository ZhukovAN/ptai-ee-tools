package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.StartScanModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.V36ScanSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.java.Log;

import java.io.File;
import java.util.List;
import java.util.UUID;

@Log
public class Project extends Utils {
    protected final String name;

    @Setter
    protected File sources;

    public Project(@NonNull final String name) {
        super();
        this.name = name;
    }

    public UUID searchProject() throws ApiException {
        ProjectLight projectLight = callApi(
                () -> projectsApi.apiProjectsLightNameGet(name),
                "PT AI project search failed");
        return (null == projectLight) ? null : projectLight.getId();
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

    public File generateReport(
            @NonNull final UUID projectId, @NonNull final UUID scanResultId,
            @NonNull final UUID template, @NonNull final ReportFormatType type, @NonNull final String locale) throws ApiException {
        ReportGenerateModel model = new ReportGenerateModel()
                .parameters(new UserReportParameters()
                        .includeDFD(true)
                        .includeGlossary(true)
                        .formatType(type)
                        .reportTemplateId(template)
                .saveAsPath(""))
                .scanResultId(scanResultId)
                .projectId(projectId)
                .localeId(locale);
        fine("Generating report for project %s, scan result %s. Report template %s, type %s, locale %s", projectId, scanResultId, template, type, locale);
        return callApi(
                () -> reportsApi.apiReportsGeneratePost(model),
                "Report generation failed");
    }

    public File generateReport(
            @NonNull final UUID projectId, @NonNull final UUID scanResultId,
            @NonNull final String template, @NonNull final ReportFormatType type, @NonNull final String locale) throws ApiException {
        List<ReportTemplateModel> templates = getReportTemplates(locale);
        ReportTemplateModel templateModel = templates.stream().filter(t -> t.getName().equalsIgnoreCase(template)).findAny().orElse(null);
        if (null == templateModel)
                throw ApiException.raise("Report generation failed", new IllegalArgumentException("PT AI template " + template + " not found"));
        return generateReport(projectId, scanResultId, templateModel.getId(), type, locale);
    }

}
