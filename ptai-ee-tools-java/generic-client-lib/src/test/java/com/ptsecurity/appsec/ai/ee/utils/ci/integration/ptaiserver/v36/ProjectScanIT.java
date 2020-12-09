package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.v36.StoreApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Project;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.StartScanModel;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheck;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheckApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import lombok.*;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.*;
import java.util.concurrent.Semaphore;

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
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project project = createProject(PROJECT);

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
    @Test
    public void testExistingProjectScanRx() {
        Semaphore semaphore = new Semaphore(1);
        semaphore.acquire();

        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project project = createProject(EXISTING_PROJECT);

        UUID scanResultId = project.scan("ptai-node");
        project.waitForComplete(scanResultId);

        /*

        ProjectsApi projectsApi = client.getProjectsApi();
        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(EXISTING_PROJECT);

        ScanApi scanApi = client.getScanApi();
        StartScanModel startScanModel = new StartScanModel();
        startScanModel.setProjectId(projectInfo.getId());
        startScanModel.setScanType(ScanType.FULL);
        scanResultId =  scanApi.apiScanStartPost(startScanModel);
        System.out.println("Scan result ID is " + scanResultId.toString());

        Single<String> accessTokenProvider = Single.defer(() -> {
            return Single.just(client.getJWT().getAccessToken());
        });
        HubConnection connection = connect(
                PTAI_URL + "/notifyApi/notifications?clientId=" + client.getId(),
                accessTokenProvider, "");

        connection.on("NeedUpdateConnectedDate", (message) -> {
            System.out.println("NeedUpdateConnectedDate: " + message);

            connection.on("ScanStarted", (data) -> {
                System.out.println("ScanStarted: " + data);
            }, ScanStartedEvent.class);

            connection.on("ScanProgress", (data) -> {
                System.out.println("ScanProgress: " + data);
            }, ScanProgressEvent.class);

            connection.on("ScanCompleted", (data) -> {
                System.out.println("ScanCompleted: " + data);
                System.out.println("Policy state is " + data.getResult().getStatistic().getPolicyState());
                semaphore.release();
            }, ScanCompleteEvent.class);

            connection.on("ScanEnqueued", (data) -> {
                System.out.println("ScanEnqueued: " + data);
            }, ScanEnqueuedEvent.class);

            // helper.getConnection().start().blockingAwait();
            SubscriptionOnNotification subscription = new SubscriptionOnNotification();
            subscription.setClientId(client.getId());
            subscription.getIds().add(scanResultId);

            subscription.setNotificationTypeName("ScanEnqueued");
            connection.send("SubscribeOnNotification", subscription);

            subscription.setNotificationTypeName("ScanProgress");
            connection.send("SubscribeOnNotification", subscription);

            subscription.setNotificationTypeName("ScanStarted");
            connection.send("SubscribeOnNotification", subscription);

            subscription.setNotificationTypeName("ScanCompleted");
            connection.send("SubscribeOnNotification", subscription);
        }, String.class);

        connection.start().blockingAwait();

        semaphore.acquire();
        // Thread.sleep(600000);

        connection.stop();
*/
        /*
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
        */
    }
}
