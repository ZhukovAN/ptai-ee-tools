package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Data;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.RawData;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.HtmlPdf;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.JsonXml;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstUnstable;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.ReportsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import jetbrains.buildServer.RunBuildException;
import jetbrains.buildServer.agent.AgentRunningBuild;
import jetbrains.buildServer.agent.BuildFinishedStatus;
import jetbrains.buildServer.agent.BuildProcess;
import jetbrains.buildServer.agent.BuildRunnerContext;
import jetbrains.buildServer.agent.artifacts.ArtifactsWatcher;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;
import java.util.concurrent.*;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;

@Slf4j
@RequiredArgsConstructor
public class AstBuildProcess implements BuildProcess, Callable<BuildFinishedStatus> {

    private Future<BuildFinishedStatus> future;

    /**
     * Build runner context used to get job parameters
     * using getRunnerParameters call
     */
    private final BuildRunnerContext buildRunnerContext;
    /**
     * Used to get globally defined settings like PT AI
     * server connection info and for logging
     */
    private final AgentRunningBuild agentRunningBuild;
    /**
     * Artifacts watcher used to mark report files as a
     * build artifacts to be stored on CI server
     */
    private final ArtifactsWatcher artifactsWatcher;

    private TeamcityAstJob job = null;

    @Override
    public BuildFinishedStatus call() {
        AbstractJob.JobExecutionResult status = ast();
        if (AbstractJob.JobExecutionResult.INTERRUPTED.equals(status))
            return BuildFinishedStatus.INTERRUPTED;
        else if (AbstractJob.JobExecutionResult.SUCCESS.equals(status))
            return BuildFinishedStatus.FINISHED_SUCCESS;
        else
            return BuildFinishedStatus.FINISHED_FAILED;
    }

    private AbstractJob.JobExecutionResult ast() {
        Map<String, String> params = buildRunnerContext.getRunnerParameters();
        Map<String, String> globals = agentRunningBuild.getSharedConfigParameters();

        boolean selectedScanSettingsUi = AST_SETTINGS_UI.equals(params.get(Params.AST_SETTINGS));
        String projectName;
        String settings = null;
        String policy = null;
        if (!selectedScanSettingsUi) {
            AiProjScanSettings scanSettings = JsonSettingsHelper.verify(params.get(Params.JSON_SETTINGS));
            projectName = scanSettings.getProjectName();
            settings = JsonSettingsHelper.minimize(params.get(Params.JSON_SETTINGS));
            policy = JsonPolicyHelper.minimize(params.get(Params.JSON_POLICY));
        } else
            projectName = params.get(Params.PROJECT_NAME);

        boolean async = AST_MODE_ASYNC.equals(params.get(Params.AST_MODE));
        boolean failIfFailed = false;
        boolean failIfUnstable = false;
        Reports reports = null;
        if (!async) {
            failIfFailed = TRUE.equals(params.get(Params.FAIL_IF_FAILED));
            failIfUnstable = TRUE.equals(params.get(Params.FAIL_IF_UNSTABLE));
            reports = ReportsHelper.convert(params);
        }

        Transfer transfer = new Transfer();
        if (StringUtils.isNotEmpty(params.get(Params.INCLUDES)))
            transfer.setIncludes(params.get(Params.INCLUDES));
        if (StringUtils.isNotEmpty(params.get(Params.EXCLUDES)))
            transfer.setExcludes(params.get(Params.EXCLUDES));
        if (StringUtils.isNotEmpty(params.get(Params.PATTERN_SEPARATOR)))
            transfer.setPatternSeparator(params.get(Params.PATTERN_SEPARATOR));
        if (StringUtils.isNotEmpty(params.get(Params.REMOVE_PREFIX)))
            transfer.setRemovePrefix(params.get(Params.REMOVE_PREFIX));
        transfer.setFlatten(TRUE.equalsIgnoreCase(params.get(Params.FLATTEN)));
        transfer.setUseDefaultExcludes(TRUE.equalsIgnoreCase(params.get(Params.USE_DEFAULT_EXCLUDES)));
        Transfers transfers = new Transfers().addTransfer(transfer);

        Map<String, String> activeConnectionParams = SERVER_SETTINGS_LOCAL.equals(params.get(Params.SERVER_SETTINGS))
                ? params
                : globals;

        job = TeamcityAstJob.builder()
                .agent(agentRunningBuild)
                .artifactsWatcher(artifactsWatcher)
                .projectName(selectedScanSettingsUi ? projectName : null)
                .settings(selectedScanSettingsUi ? null : settings)
                .policy(selectedScanSettingsUi ?  null : policy)
                .connectionSettings(ConnectionSettings.builder()
                        .url(activeConnectionParams.get(Params.URL))
                        .insecure(TRUE.equals(activeConnectionParams.get(Params.INSECURE)))
                        .credentials(TokenCredentials.builder().token(activeConnectionParams.get(Params.TOKEN)).build())
                        .caCertsPem(activeConnectionParams.get(Params.CERTIFICATES))
                        .build())
                .fullScanMode(TRUE.equals(params.get(Params.FULL_SCAN_MODE)))
                .verbose(TRUE.equals(params.get(Params.VERBOSE)))
                .transfers(transfers)
                .async(async)
                .build();
        if (null != reports) {
            for (Report report : reports.getReport())
                HtmlPdf.builder().owner(job).report(report).build().attach(job);
            for (Data data : reports.getData())
                JsonXml.builder().owner(job).data(data).build().attach(job);
            for (RawData rawData : reports.getRaw())
                RawJson.builder().owner(job).rawData(rawData).build().attach(job);
        }
        if (failIfFailed) new FailIfAstFailed().attach(job);
        if (failIfUnstable) new FailIfAstUnstable().attach(job);

        return job.execute();
    }

    @Override
    public void start() throws RunBuildException {
        try {
            future = Executors.newSingleThreadExecutor().submit(this);
        } catch (final RejectedExecutionException e) {
            throw new RunBuildException(e);
        }
    }

    @Override
    public boolean isInterrupted() {
        return future.isCancelled() && isFinished();
    }

    @Override
    public boolean isFinished() {
        return future.isDone();
    }

    @Override
    public void interrupt() {
        if (null != job)
        job.stop();
        future.cancel(true);
    }

    @NonNull
    @Override
    public BuildFinishedStatus waitFor() throws RunBuildException {
        try {
            return future.get();
        } catch (final InterruptedException | ExecutionException e) {
            throw new RunBuildException(e);
        } catch (final CancellationException e) {
            return BuildFinishedStatus.INTERRUPTED;
        }
    }
}
