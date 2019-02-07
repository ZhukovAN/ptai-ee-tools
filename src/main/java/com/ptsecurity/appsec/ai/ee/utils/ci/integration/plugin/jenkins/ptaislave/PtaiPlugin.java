package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor.PtaiPluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleBuild;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.TreeMap;

@Slf4j
@ToString
public class PtaiPlugin extends Builder implements SimpleBuildStep {
    private static final String consolePrefix = Messages.console_message_prefix();

    @Getter
    private String sastConfigName;

    @Getter
    private String uiProject;

    @Getter
    private String sastAgentName;

    @Getter
    private ArrayList<PtaiTransfer> transfers;

    public final void setTransfers(final ArrayList<PtaiTransfer> transfers) {
        if (transfers == null)
            this.transfers = new ArrayList<PtaiTransfer>();
        else
            this.transfers = transfers;
    }

    @DataBoundConstructor
    public PtaiPlugin(final String sastConfigName,
                      final String uiProject,
                      final String sastAgentName,
                      final ArrayList<PtaiTransfer> transfers) {
        this.sastConfigName = sastConfigName;
        this.uiProject = uiProject;
        this.sastAgentName = sastAgentName;
        this.transfers = transfers;
    }

    private TreeMap<String, String> getEnvironmentVariables(final Run<?, ?> build, final TaskListener listener) {
        try {
            final TreeMap<String, String> env = build.getEnvironment(listener);
            if (build instanceof AbstractBuild) {
                env.putAll(((AbstractBuild) build).getBuildVariables());
            }
            return env;
        } catch (Exception e) {
            throw new RuntimeException(Messages.exception_failedToGetEnvVars(), e);
        }
    }

    @Override
    public void perform(@Nonnull Run<?, ?> build, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener) throws InterruptedException, IOException {
        Jenkins jenkins = Jenkins.get();
        final BuildEnv currentBuildEnv = new BuildEnv(getEnvironmentVariables(build, listener), workspace, build.getTimestamp());
        final BuildEnv targetBuildEnv = null;
        final BuildInfo buildInfo = new BuildInfo(listener, consolePrefix, jenkins.getRootPath(), currentBuildEnv, targetBuildEnv);
        buildInfo.setEffectiveEnvironmentInBuildInfo();

        String ptaiHostUrl = this.getSastConfig(sastConfigName).getSastConfigPtaiHostUrl();
        FileUploader uploader = new FileUploader(listener, transfers, ptaiHostUrl);
        buildInfo.println("Upload: " + workspace.act(uploader));

        PtaiSastConfig cfg = getDescriptor().getSastConfig(sastConfigName);
        PtaiJenkinsApiClient apiClient = new PtaiJenkinsApiClient();
        apiClient.setDebugging(true);
        RemoteAccessApi api = new RemoteAccessApi(apiClient);
        api.getApiClient().setBasePath(this.getSastConfig(sastConfigName).getSastConfigJenkinsHostUrl());
        String l_strJobName = apiClient.convertJobName(cfg.getSastConfigJenkinsJobName());
        String json = "{\"parameter\": [{\"name\":\"workMode\", \"value\":\"123\"}, {\"name\":\"sastNode\", \"value\":\"high\"}]}";
        try {
            FreeStyleProject prj = api.getJob(l_strJobName);
            api.postJobBuild(l_strJobName, json, null, null);
            prj = api.getJob(l_strJobName);
        } catch (Exception e) {}
        // l_objApi.postJobBuild();
    }

    protected void fixup(final Run<?, ?> build, final BuildInfo buildInfo) {
        // provide a hook for the plugin impl to get at other internals - ie Hudson.getInstance is null when remote from a publisher!!!!!
        // as is Exceutor.currentExecutor, Computer.currentComputer - it's a wilderness out there!
    }

    @Override
    public PtaiPluginDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(PtaiPluginDescriptor.class);
    }

    public PtaiSastConfig getSastConfig(final String sastConfigName) {
        return getDescriptor().getSastConfig(sastConfigName);
    }
}