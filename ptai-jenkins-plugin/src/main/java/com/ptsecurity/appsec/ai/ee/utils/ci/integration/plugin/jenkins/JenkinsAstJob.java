package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.JsonAstJobSetupOperationsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.UiAstJobSetupOperationsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations.JenkinsAstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations.JenkinsFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildInfo;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.Run;
import hudson.model.TaskListener;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

@Slf4j
@Getter
@Setter
@SuperBuilder
@ToString(callSuper = true)
public class JenkinsAstJob extends GenericAstJob implements TextOutput {
    @NonNull
    protected Plugin plugin;

    @NonNull
    protected Run<?, ?> run;
    /**
     * CI workspace folder
     *
     * @param workspace New value for CI workspace folder
     * @return The current value of CI workspace folder
     */
    @NonNull
    protected FilePath workspace;

    /**
     * Jenkins launcher that is used for function call on a
     * remote scan agent. As build task may be executed on
     * a remote agent, we need to take special care for
     * resource-consuming operations such as source code
     * archive creation and reports save to workspace
     *
     * @param launcher New value for Jenkins launcher
     * @return The current value of Jenkins launcher
     */
    @NonNull
    @ToString.Exclude
    protected Launcher launcher;

    /**
     * Listener allow us to send log messages from remote
     * scan agent to Jenkins server
     *
     * @param listener New value for listener
     * @return The current value of listener
     */
    @NonNull
    @ToString.Exclude
    protected TaskListener listener;

    /**
     * Build info contains environment variables that may
     * be used for macro replacement
     *
     * @param buildInfo New value for build info
     * @return The current value of build info
     */
    @NonNull
    protected BuildInfo buildInfo;

    /**
     * List of transfers, i.e. source files to be zipped
     * and sent to PT AI server
     *
     * @param transfers New value for list of transfers
     * @return The current value of list of transfers
     */
    private List<Transfer> transfers;

    protected String settings;

    protected String policy;

    @Override
    protected void init() throws GenericException {
        astOps = JenkinsAstOperations.builder()
                .owner(this)
                .build();
        fileOps = JenkinsFileOperations.builder()
                .owner(this)
                .build();

        if (null != settings)
            setupOps = JsonAstJobSetupOperationsImpl.builder()
                .jsonSettings(settings)
                .jsonPolicy(policy)
                .owner(this)
                .build();
        else
            setupOps = UiAstJobSetupOperationsImpl.builder()
                    .owner(this)
                    .build();
    }

    @Override
    public JobExecutionResult processException(@NonNull final GenericException e) {
        JobExecutionResult res = super.processException(e);
        plugin.setBuildResult(run, res, e);
        return res;
    }

    public String replaceMacro(@NonNull String value) {
        return replaceMacro(value, getBuildInfo().getEnvVars());
    }

    public String replaceMacro(@NonNull String value, Map<String, String> replacements) {
        return Util.replaceMacro(value, replacements);
    }
}
