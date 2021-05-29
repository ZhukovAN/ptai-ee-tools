package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.v36.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Project;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.StartScanModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import lombok.*;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;

import java.io.File;
import java.util.*;
import java.util.concurrent.Semaphore;

@Tag("integration-legacy")
public class ProjectScanIT extends BaseAstIT {
    protected static final String EXISTING_PROJECT = "app01";
    protected static final UUID EXISTING_SCAN_RESULT_ID = UUID.fromString("a221c55d-038b-41ed-91e8-5c9d67cb3337");
    protected static final String PROJECT = "app01-" + UUID.randomUUID().toString();

    @SneakyThrows
    public void testExistingProjectSettings() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);
        V36ScanSettings scanSettings = projectsApi.apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectInfo.getId(), projectInfo.getSettingsId());
        Assertions.assertEquals(projectInfo.getSettingsId(), scanSettings.getId());
        System.out.println(scanSettings);
    }

    @SneakyThrows
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
    public void testSourcesUpload() {
        Transfers transfers = new Transfers();
        transfers.add(Transfer.builder().includes("**/*").build());
        File zip = FileCollector.collect(transfers, SOURCES_FOLDER.toFile(), client);

        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);

        StoreApi storeApi = client.getStoreApi();
        storeApi.uploadSources(projectInfo.getId(), zip);
    }

    @SneakyThrows
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
        File issues = REPORT_FOLDER.resolve("report.json").toFile();
        FileUtils.copyFile(issuesTempFile, issues);
        FileUtils.forceDelete(issuesTempFile);
    }

    @SneakyThrows
    public void testGetExistingScanResults() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);
        File issuesTempFile = projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectInfo.getId(), EXISTING_SCAN_RESULT_ID, null);
        File issues = REPORT_FOLDER.resolve("report.json").toFile();
        FileUtils.copyFile(issuesTempFile, issues);
        FileUtils.forceDelete(issuesTempFile);
    }

    @SneakyThrows
    public void testGetExistingPolicyAssessment() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);
        ScanResult scanResult = projectsApi.apiProjectsProjectIdScanResultsScanResultIdGet(projectInfo.getId(), EXISTING_SCAN_RESULT_ID);
        System.out.println("Policy state is " + scanResult.getStatistic().getPolicyState());
    }

    @SneakyThrows
    public void testGetExistingPoliciesAssessment() {
        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);
        List<ScanResult> scanResults = projectsApi.apiProjectsProjectIdScanResultsGet(projectInfo.getId(), AuthScopeType.VIEWER);
        scanResults.forEach(System.out::println);
    }

    @RequiredArgsConstructor
    public final class SubscriptionOnNotification {
        @Getter @Setter
        public String ClientId;
        @Getter @Setter
        public String NotificationTypeName;
        @Getter @Setter
        public Set<UUID> Ids = new HashSet<>();

        @Getter
        public final Date CreatedDate;

        public SubscriptionOnNotification() {
            this.CreatedDate = new Date();
        }
    }

    @Getter @Setter @ToString
    public final class ScanEnqueuedEvent {
        protected ScanResult result;
    }

    @Getter @Setter @ToString
    public final class ScanStartedEvent {
        protected ScanResult result;
        protected V36ScanSettings settings;
    }

    @Getter @Setter @ToString
    public final class ScanProgressEvent {
        protected UUID scanResultId;
        protected ScanProgress progress;
        protected UUID Id;
    }

    @Getter @Setter @ToString
    public final class ScanCompleteEvent {
        protected ScanResult result;
    }


    @SneakyThrows
    public void testExistingProjectScanRx() {
        Semaphore semaphore = new Semaphore(1);
        semaphore.acquire();

        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project project = createProject(EXISTING_PROJECT);

        UUID scanResultId = project.scan();
        project.waitForComplete(scanResultId);
    }
}
