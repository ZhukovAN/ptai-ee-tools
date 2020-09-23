package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.v36.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Project;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanAgentApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.StartScanModel;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheck;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheckApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.V36ScanSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings.ProgrammingLanguage.*;
import static org.joor.Reflect.on;

public class ProjectScanIT extends BaseIT {
    protected static final String EXISTING_PROJECT = "app01";
    protected static final UUID EXISTING_SCAN_RESULT_ID = UUID.fromString("a221c55d-038b-41ed-91e8-5c9d67cb3337");
    protected static final String PROJECT = "app01-" + UUID.randomUUID().toString();

    @SneakyThrows
    @Test
    public void testExistingProjectSettings() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);
        V36ScanSettings scanSettings = projectsApi.apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectInfo.getId(), projectInfo.getSettingsId());
        Assertions.assertEquals(projectInfo.getSettingsId(), scanSettings.getId());
        System.out.println(scanSettings);
    }

    @SneakyThrows
    @Test
    public void testAllExistingProjectSettings() {
        ProjectsApi projectsApi = client.getProjectsApi();
        List<Project> projects = projectsApi.apiProjectsGet(true);
        for (Project project : projects) {
            ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(project.getName());
            System.out.println(projectInfo);
            try {
                V36ScanSettings scanSettings = projectsApi.apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectInfo.getId(), projectInfo.getSettingsId());
                Assertions.assertEquals(projectInfo.getSettingsId(), scanSettings.getId());
                System.out.println(scanSettings);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }

    @SneakyThrows
    @Test
    public void testSourcesUpload() {
        Transfers transfers = new Transfers();
        transfers.add(Transfer.builder().includes("**/*").build());
        File zip = FileCollector.collect(transfers, TEMPSRCFOLDER, client);

        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);

        StoreApi storeApi = client.getStoreApi();
        storeApi.uploadSources(projectInfo.getId(), zip);
    }

    @SneakyThrows
    @Test
    public void testExistingProjectScan() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);

        ScanApi scanApi = client.getScanApi();
        StartScanModel startScanModel = new StartScanModel();
        startScanModel.setProjectId(projectInfo.getId());
        startScanModel.setScanType(ScanType.FULL);
        UUID scanResultId =  scanApi.apiScanStartPost(startScanModel);
        System.out.println("Scan result ID is " + scanResultId.toString());

        Stage stage;
        ScanResult scanResult;
        do {
            scanResult = projectsApi.apiProjectsProjectIdScanResultsScanResultIdGet(projectInfo.getId(), scanResultId);
            System.out.println(scanResult);
            ScanProgress progress = scanResult.getProgress();
            stage = progress.getStage();
            Thread.sleep(5000);
        } while (!Stage.DONE.equals(stage) && !Stage.ABORTED.equals(stage) && !Stage.FAILED.equals(stage));
        Assertions.assertEquals(Stage.DONE, stage);
        System.out.println("Policy state is " + scanResult.getStatistic().getPolicyState());
        File issuesTempFile = projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectInfo.getId(), scanResultId, null);
        File issues = TEMPREPORTFOLDER.toPath().resolve("report.json").toFile();
        FileUtils.copyFile(issuesTempFile, issues);
        FileUtils.forceDelete(issuesTempFile);
    }

    @SneakyThrows
    @Test
    public void testGetExistingScanResults() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);
        File issuesTempFile = projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectInfo.getId(), EXISTING_SCAN_RESULT_ID, null);
        File issues = TEMPREPORTFOLDER.toPath().resolve("report.json").toFile();
        FileUtils.copyFile(issuesTempFile, issues);
        FileUtils.forceDelete(issuesTempFile);
    }

    @SneakyThrows
    @Test
    public void testReportTemplatesList() {
        Utils utils = new Utils();
        utils.setUrl(client.getUrl());
        utils.setToken(client.getToken());
        utils.setCaCertsPem(client.getCaCertsPem());
        utils.init();

        List<ReportTemplateModel> templates = utils.getReportTemplates();
        for (ReportTemplateModel template : templates) {
            System.out.println(template.getName());
        }
    }

    @SneakyThrows
    @Test
    public void testReportGeneration() {
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project project = new com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project(EXISTING_PROJECT);
        project.setUrl(client.getUrl());
        project.setToken(client.getToken());
        project.setCaCertsPem(client.getCaCertsPem());
        project.init();

        List<ReportTemplateModel> templates = project.getReportTemplates();
        int templateIdx = (int) Math.round(Math.random() * templates.size());
        UUID templateId = templates.get(templateIdx).getId();
        UUID projectId = project.searchProject();

        File reportTempFile = project.generateReport(projectId, EXISTING_SCAN_RESULT_ID, "\"Scan Result\"", ReportFormatType.HTML, "ru-RU");
        reportTempFile = project.generateReport(projectId, EXISTING_SCAN_RESULT_ID, "\"Scan Result\"", ReportFormatType.JSON, "ru-RU");
        reportTempFile = project.generateReport(projectId, EXISTING_SCAN_RESULT_ID, "\"Scan Result\"", ReportFormatType.PDF, "ru-RU");
        File report = TEMPREPORTFOLDER.toPath().resolve("report.json").toFile();
        // FileUtils.copyFile(issuesTempFile, issues);
        // FileUtils.forceDelete(issuesTempFile);
    }

    @SneakyThrows
    @Test
    public void testGetExistingPolicyAssessment() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);
        ScanResult scanResult = projectsApi.apiProjectsProjectIdScanResultsScanResultIdGet(projectInfo.getId(), EXISTING_SCAN_RESULT_ID);
        System.out.println("Policy state is " + scanResult.getStatistic().getPolicyState());
    }

    @SneakyThrows
    @Test
    public void testGetExistingPoliciesAssessment() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);
        List<ScanResult> scanResults = projectsApi.apiProjectsProjectIdScanResultsGet(projectInfo.getId(), AuthScopeType.VIEWER);
        scanResults.forEach(System.out::println);
    }

    @SneakyThrows
    @Test
    public void testHealthCheck() {
        HealthCheckApi healthCheckApi = client.getHealthCheckApi();
        HealthCheck summary = healthCheckApi.healthSummaryGet();
        System.out.println("Health check summary is " + summary);
    }

    @SneakyThrows
    @Test
    public void testNewProjectScan() {
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project project = new com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project(PROJECT);
        project.setUrl(client.getUrl());
        project.setToken(client.getToken());
        project.setCaCertsPem(client.getCaCertsPem());
        project.init();

        SETTINGS.setUseIssueTrackerIntegration(false);
        SETTINGS.setSendEmailWithReportsAfterScan(false);
        UUID projectId = project.setupFromJson(SETTINGS, POLICY);

        Transfers transfers = new Transfers();
        transfers.add(Transfer.builder().includes("**/*").build());
        File zip = FileCollector.collect(transfers, TEMPSRCFOLDER, client);
        project.setSources(zip);
        project.upload();

        UUID scanResultId = project.scan("ptai-node");

        Stage stage = null;
        ScanProgress previousProgress = null;
        ScanResultStatistic previousStatistic = null;

        do {
            Thread.sleep(5000);
            ScanResult state = project.poll(projectId, scanResultId);
            ScanProgress progress = state.getProgress();
            ScanResultStatistic statistic = state.getStatistic();
            if (null != progress || !progress.equals(previousProgress)) {
                String progressInfo = "AST stage: " + progress.getStage() + ", percentage: " + progress.getValue();
                project.info(progressInfo);
                previousProgress = progress;
            }
            if (null != statistic || !statistic.equals(previousStatistic)) {
                project.info("Scan duration: %s", statistic.getScanDuration());
                if (0 != statistic.getTotalFileCount())
                    project.info("Scanned files: %d out of %d", statistic.getScannedFileCount(), statistic.getTotalFileCount());
                previousStatistic = statistic;
            }
            if (null != progress) stage = progress.getStage();
        } while (!Stage.DONE.equals(stage) && !Stage.ABORTED.equals(stage) && !Stage.FAILED.equals(stage));
    }
}
