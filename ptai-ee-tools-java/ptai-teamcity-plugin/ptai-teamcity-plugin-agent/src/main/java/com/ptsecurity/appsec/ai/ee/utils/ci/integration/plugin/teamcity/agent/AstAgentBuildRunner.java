package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import jetbrains.buildServer.RunBuildException;
import jetbrains.buildServer.agent.*;
import jetbrains.buildServer.agent.artifacts.ArtifactsWatcher;
import org.jetbrains.annotations.NotNull;

public class AstAgentBuildRunner implements AgentBuildRunner, AgentBuildRunnerInfo {
    /**
     * Can be used to notify agent artifacts publisher about new artifacts to be published during the build
     */
    private final ArtifactsWatcher artifactsWatcher;

    public AstAgentBuildRunner(@NotNull final ArtifactsWatcher artifactsWatcher) {
        this.artifactsWatcher = artifactsWatcher;
    }

    @NotNull
    @Override
    public BuildProcess createBuildProcess(@NotNull AgentRunningBuild agentRunningBuild, @NotNull BuildRunnerContext buildRunnerContext) throws RunBuildException {
        return new AstBuildProcess(agentRunningBuild, buildRunnerContext, artifactsWatcher);
    }

    @NotNull
    @Override
    public AgentBuildRunnerInfo getRunnerInfo() {
        return this;
    }

    @NotNull
    @Override
    public String getType() {
        return Constants.RUNNER_TYPE;
    }

    @Override
    public boolean canRun(@NotNull BuildAgentConfiguration buildAgentConfiguration) {
        return true;
    }
}
