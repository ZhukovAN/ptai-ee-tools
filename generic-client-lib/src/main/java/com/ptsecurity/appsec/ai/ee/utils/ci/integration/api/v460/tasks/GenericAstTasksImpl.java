package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v460.tasks;

import com.microsoft.signalr.HubConnection;
import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v460.api.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v460.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v460.converters.EnumsConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v460.converters.IssuesConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v460.converters.ScanErrorsConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;

import java.io.File;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.scan.progress.Stage.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v460.converters.IssuesConverter.convert;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

@Slf4j
public class GenericAstTasksImpl extends AbstractTaskImpl implements GenericAstTasks {
    public GenericAstTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    public void upload(@NonNull final UUID projectId, @NonNull final File sources) throws GenericException {
        call(() -> client.getStoreApi().apiStoreProjectIdSourcesPost(projectId, true, true, sources), "PT AI project sources upload failed");
    }

    @Override
    public UUID startScan(@NonNull UUID projectId, boolean fullScanMode) throws GenericException {
        StartScanModel startScanModel = new StartScanModel();
        // Setup scan mode: full or incremental. Default mode is
        // incremental, but it can be overridden by JSON settings or forced from UI
        ScanType scanType = fullScanMode ? ScanType.FULL : ScanType.INCREMENTAL;
        startScanModel.setScanType(scanType);
        return call(
                () -> client.getScanQueueApi().apiScansProjectIdStartPost(projectId, startScanModel),
                "PT AI project scan start failed");
    }

    @Override
    public String getScanResultUrl(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
        return call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGetCall(projectId, scanResultId, null).request().url().toString(),
                "Failed to get AST result URL");
    }

    public static class ProjectPollingThread implements Runnable {
        protected final ApiClient client;

        protected final UUID projectId;
        protected final UUID scanResultId;
        protected final BlockingQueue<Stage> queue;

        protected final Thread thread;

        protected boolean exit = false;

        public ProjectPollingThread(@NonNull final ApiClient client, @NonNull final ScanBrief scanBrief, final BlockingQueue<@NonNull Stage> queue) {
            log.trace("AST job state polling thread created for project {}, scan result {}", scanBrief.getProjectId(), scanBrief.getId());
            this.client = client;
            this.projectId = scanBrief.getProjectId();
            this.scanResultId = scanBrief.getId();
            this.queue = queue;

            this.thread = new Thread(this);
            this.thread.start();
        }

        @Override
        public void run() {
            final int interval = client.getAdvancedSettings().getInt(AdvancedSettings.SettingInfo.AST_JOB_POLL_INTERVAL);
            while (true) {
                try {
                    Thread.sleep(1000);
                    if (exit) break;
                    if (interval > Duration.between(lastResetTime, LocalDateTime.now()).getSeconds()) continue;
                    log.trace("Poll {} project {} scan state", projectId, scanResultId);
                    ScanResultModel scanResult = call(
                            () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                            "Get project scan result failed");
                    reset();
                    // TODO: Properly process this
                    if (null == scanResult.getProgress()) break;
                    if (null == scanResult.getProgress().getStage()) break;
                    @NonNull Stage stage = EnumsConverter.convert(scanResult.getProgress().getStage());
                    if (DONE != stage && ABORTED != stage && FAILED != stage) continue;
                    log.trace("Stop job from polling thread");
                    queue.add(stage);
                    break;
                } catch (GenericException e) {
                    log.error("Project polling thread failed to get scan state", e);
                    break;
                } catch (InterruptedException e) {
                    log.error("Project polling thread interrupted", e);
                    break;
                }
            }
        }

        public void stop() {
            exit = true;
        }

        @ToString.Exclude
        @NonNull
        protected LocalDateTime lastResetTime = LocalDateTime.now();

        public synchronized void reset() {
            lastResetTime = LocalDateTime.now();
            log.trace("Reset polling thread last activity time to {}", lastResetTime);
        }
    }

    @Override
    public void waitForComplete(@NonNull ScanBrief scanBrief) throws InterruptedException {
        // Semaphore-based implementation was replaced by queue-based as
        // waitForComplete unblocking may be done on several events like
        // ScanCompleted and ScanProgress with aborted and failed stage values
        BlockingQueue<Stage> queue = new LinkedBlockingDeque<>();

        // As sometimes notifications get lost somewhere we need to implement parallel polling thread
        ProjectPollingThread pollingThread = new ProjectPollingThread(client, scanBrief, queue);
        HubConnection connection = client.createSignalrConnection(scanBrief, queue, pollingThread);
        client.wait(connection, scanBrief);

        Stage stage = queue.take();
        connection.stop().blockingAwait();
        pollingThread.stop();

        scanBrief.setState(FAILED == stage
                ? ScanBrief.State.FAILED
                : ABORTED == stage
                ? ScanBrief.State.ABORTED
                : DONE == stage
                ? ScanBrief.State.DONE
                : ScanBrief.State.UNKNOWN);
    }

    public void stop(@NonNull UUID scanResultId) throws GenericException {
        log.debug("Calling scan stop for scan result ID {}", scanResultId);
        // TODO: Implement different approach to stop task that is enqueued but not
        //  started yet. PT AI 4.3 doesn't stop these jobs, so we need to delete scan
        //  result as PT AI viewer does
        call(
                () -> client.getScanQueueApi().apiScansScanResultIdStopPost(scanResultId),
                "PT AI project scan stop failed");
    }

    @NonNull
    @Override
    public ScanBrief createScanBrief(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException {
        String projectName = new ProjectTasksImpl(client).searchProject(projectId);
        ScanResultModel scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                "Get project scan result failed");
        log.debug("Project {} scan result {} load complete", projectId, scanResultId);

        ScanSettingsModel scanSettings = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectId, scanResult.getSettingsId()),
                "Get project scan settings failed");
        log.debug("Project {} scan result {} settings loaded", projectId, scanResultId);

        ServerVersionTasks serverVersionTasks = new ServerVersionTasksImpl(client);
        Map<ServerVersionTasks.Component, String> versions = call(serverVersionTasks::current, "PT AI server API version read ailed");

        return ScanBrief.builder()
                .apiVersion(client.getApiVersion())
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
        ScanResultModel scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(scanBrief.getProjectId(), scanBrief.getId()),
                "Get project scan result failed");
        log.debug("Project {} scan result {} load complete", scanBrief.getProjectId(), scanBrief.getId());

        log.trace("Getting scan result statistics");
        ScanStatisticModel statistic = call(
                () -> Objects.requireNonNull(scanResult.getStatistic(), "Scan result statistics is null"),
                "Get scan result statistics failed");
        log.trace("Converting v.4.3 scan result statistics to version-independent data");
        call(
                () -> scanBrief.setStatistics(convert(statistic, scanResult)),
                "Scan result statistics conversion failed");
        log.trace("Setting scan brief policy assessment state");
        call(
                () -> scanBrief.setPolicyState(IssuesConverter.convert(Objects.requireNonNull(statistic.getPolicyState(), "Scan result policy state is null"))),
                "Scan result policy state stage conversion failed");
    }

    @Override
    public ScanResult getScanResult(@NonNull UUID projectId, @NonNull UUID scanResultId) throws GenericException {
        ScanResultModel scanResult = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGet(projectId, scanResultId),
                "Get project scan result failed");
        log.debug("Project {} scan result {} load complete", projectId, scanResultId);
        List<VulnerabilityModel> issues = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectId, scanResultId),
                "Get project scan result failed");
        log.debug("Project {} scan result {} issues load complete", projectId, scanResultId);

        log.trace("Loading issues into temporal files");
        Map<Reports.Locale, Map<String, String>> localizedIssuesHeaders = new HashMap<>();
        for (Reports.Locale locale : Reports.Locale.values()) {
            log.trace("Getting issues data using {} locale", locale);
            Map<String, String> headers = call(
                    () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesHeadersGet(projectId, scanResultId, locale.getValue()),
                    "PT AI project localized scan status JSON read failed");
            log.debug("Localized ({}) issues load complete", locale);
            localizedIssuesHeaders.put(locale, headers);
        }

        log.trace("Loading project {} scan settings {}", projectId, scanResult.getSettingsId());
        ScanSettingsModel scanSettings = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGet(projectId, scanResult.getSettingsId()),
                "Get project scan settings failed");
        log.debug("Project {} scan result {} settings loaded", projectId, scanResultId);

        String projectName = call(() -> Objects.requireNonNull(new ProjectTasksImpl(client).searchProject(projectId)), "Project not found");
        ServerVersionTasks serverVersionTasks = new ServerVersionTasksImpl(client);
        Map<ServerVersionTasks.Component, String> versions = call(serverVersionTasks::current, "PT AI server API version read ailed");

        ScanResult res = call(
                () -> convert(projectName, scanResult, issues, localizedIssuesHeaders, scanSettings, client.getConnectionSettings().getUrl(), versions), "Project scan result convert failed");

        log.debug("Project scan result conversion complete");
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
        scanResult.setPtaiAgentName(scanBrief.getPtaiAgentName());
        return scanResult;
    }

    public List<Error> getScanErrors(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException {
        List<ScanErrorModel> errors = call(
                () -> client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdErrorsGet(projectId, scanResultId),
                "PT AI project scan errors read failed");
        if (null == errors || errors.isEmpty()) return null;
        return errors.stream().map(ScanErrorsConverter::convert).collect(Collectors.toList());
    }
 }