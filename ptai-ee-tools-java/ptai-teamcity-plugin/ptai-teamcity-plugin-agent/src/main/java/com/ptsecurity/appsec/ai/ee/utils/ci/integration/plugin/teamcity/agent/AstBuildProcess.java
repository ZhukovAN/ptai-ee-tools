package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.UrlHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import jetbrains.buildServer.RunBuildException;
import jetbrains.buildServer.agent.AgentRunningBuild;
import jetbrains.buildServer.agent.BuildFinishedStatus;
import jetbrains.buildServer.agent.BuildProcess;
import jetbrains.buildServer.agent.BuildRunnerContext;
import jetbrains.buildServer.agent.artifacts.ArtifactsWatcher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.concurrent.*;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.SERVER_SETTINGS_GLOBAL;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.TRUE;

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
     * server conection info and for logging
     */
    private final AgentRunningBuild agentRunningBuild;
    /**
     * Artifacts watcher used to mark report files as a
     * build artifacts to be stored on CI server
     */
    private final ArtifactsWatcher artifactsWatcher;

    private TeamcityAstJob job = null;

    @Override
    public BuildFinishedStatus call() throws Exception {
        AstJob.JobFinishedStatus status = ast();
        if (AstJob.JobFinishedStatus.INTERRUPTED.equals(status))
            return BuildFinishedStatus.INTERRUPTED;
        else if (AstJob.JobFinishedStatus.SUCCESS.equals(status))
            return BuildFinishedStatus.FINISHED_SUCCESS;
        else
            return BuildFinishedStatus.FINISHED_FAILED;
    }

    protected String validateNotEmpty(final String value) {
        if (StringUtils.isNotEmpty(value)) return value;
        throw new IllegalArgumentException(Resources.validator_check_field_empty());
    }

    protected String validateUrl(final String value) {
        String url = validateNotEmpty(value);
        if (UrlHelper.checkUrl(url)) return url;
        throw new IllegalArgumentException(Resources.validator_check_url_invalid());
    }

    private AstJob.JobFinishedStatus ast() throws Exception {
        Map<String, String> params = buildRunnerContext.getRunnerParameters();
        Map<String, String> globals = agentRunningBuild.getSharedConfigParameters();

        boolean globalSettingsUsed = SERVER_SETTINGS_GLOBAL.equalsIgnoreCase(params.get(Params.SERVER_SETTINGS));
        if (!globalSettingsUsed) globals = params;

        String jsonSettings = null;
        String jsonPolicy = null;

        String projectName = null;

        if (Constants.AST_SETTINGS_JSON.equalsIgnoreCase(params.get(Params.AST_SETTINGS))) {
            ScanSettings scanSettings = JsonSettingsHelper.verify(params.get(Params.JSON_SETTINGS));
            projectName = validateNotEmpty(scanSettings.getProjectName());
            jsonSettings = JsonSettingsHelper.minimize(params.get(Params.JSON_SETTINGS));
            jsonPolicy = JsonPolicyHelper.minimize(params.get(Params.JSON_POLICY));
        } else
            projectName = validateNotEmpty(params.get(Params.PROJECT_NAME));

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

        job = TeamcityAstJob.builder()
                .name(projectName)
                .jsonSettings(jsonSettings)
                .jsonPolicy(jsonPolicy)
                .verbose(TRUE.equalsIgnoreCase(params.get(Params.VERBOSE)))
                // .prefix(CONSOLE_PREFIX)
                .url(validateUrl(globals.get(Params.URL)))
                .token(validateNotEmpty(globals.get(Params.TOKEN)))
                .insecure(TRUE.equalsIgnoreCase(globals.get(Params.INSECURE)))
                // .async(workMode instanceof WorkModeAsync)
                .failIfFailed(TRUE.equalsIgnoreCase(params.get(Params.FAIL_IF_FAILED)))
                .failIfUnstable(TRUE.equalsIgnoreCase(params.get(Params.FAIL_IF_UNSTABLE)))
                .agent(agentRunningBuild)
                .artifactsWatcher(artifactsWatcher)
                .transfers(new Transfers().addTransfer(transfer))
                .build();
        if (StringUtils.isNotEmpty(globals.get(Params.CERTIFICATES)))
            job.setCaCertsPem(globals.get(Params.CERTIFICATES));
        job.init();
        // TODO: Add async mode support
        /*
        if (workMode instanceof WorkModeSync) {
            WorkModeSync workModeSync = (WorkModeSync) workMode;
            Reports reports = BaseReport.validate(workModeSync.getReports(), job);
            if (null != reports)
                job.setReports(reports);
        }
        */
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

    @NotNull
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
