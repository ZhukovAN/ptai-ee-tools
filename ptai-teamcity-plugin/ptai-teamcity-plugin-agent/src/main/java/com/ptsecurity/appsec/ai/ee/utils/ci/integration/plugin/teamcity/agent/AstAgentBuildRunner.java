package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import jetbrains.buildServer.RunBuildException;
import jetbrains.buildServer.agent.*;
import jetbrains.buildServer.agent.artifacts.ArtifactsWatcher;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AstAgentBuildRunner implements AgentBuildRunner, AgentBuildRunnerInfo {
    /**
     * Can be used to notify agent artifacts publisher about new artifacts to be published during the build
     */
    private final ArtifactsWatcher artifactsWatcher;

    @NonNull
    @Override
    public BuildProcess createBuildProcess(@NonNull AgentRunningBuild agentRunningBuild, @NonNull BuildRunnerContext buildRunnerContext) throws RunBuildException {
        return new AstBuildProcess(buildRunnerContext, agentRunningBuild, artifactsWatcher);
    }

    @NonNull
    @Override
    public AgentBuildRunnerInfo getRunnerInfo() {
        return this;
    }

    @NonNull
    @Override
    public String getType() {
        return Constants.RUNNER_TYPE;
    }

    @Override
    public boolean canRun(@NonNull BuildAgentConfiguration buildAgentConfiguration) {
        return true;
    }
}
