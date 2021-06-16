package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.UrlHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob;
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

        job = TeamcityAstJob.builder()
                .agent(agentRunningBuild)
                .artifactsWatcher(artifactsWatcher)
                .globals(globals)
                .params(params)
                .build();
        job.init();
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
