package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.CredentialsAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.TokenAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PtaiPluginDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildEnv;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildInfo;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import hudson.AbortException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.*;
import hudson.tasks.Builder;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.kohsuke.stapler.DataBoundConstructor;
import org.parboiled.common.StringUtils;

import javax.annotation.Nonnull;
import java.io.*;
import java.util.*;

import static org.apache.commons.lang3.StringUtils.trimToNull;

@Slf4j
@ToString
public class PtaiPlugin extends Builder implements SimpleBuildStep {
    private static final String consolePrefix = com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.console_message_prefix();

    @Getter
    private final String sastConfigName;

    @Getter
    private final String uiProject;

    @Getter
    private final boolean failIfSastFailed;

    @Getter
    private final boolean failIfSastUnstable;

    @Getter
    private final String sastAgentNodeName;

    @Getter
    private final boolean verbose;

    @Getter
    private ArrayList<PtaiTransfer> transfers;

    public final void setTransfers(final ArrayList<PtaiTransfer> transfers) {
        if (transfers == null)
            this.transfers = new ArrayList<>();
        else
            this.transfers = transfers;
    }

    @DataBoundConstructor
    public PtaiPlugin(final String sastConfigName,
                      final String uiProject,
                      final boolean failIfSastFailed,
                      final boolean failIfSastUnstable,
                      final String sastAgentNodeName,
                      final boolean verbose,
                      final ArrayList<PtaiTransfer> transfers) {
        this.sastConfigName = sastConfigName;
        this.uiProject = uiProject;
        this.failIfSastFailed = failIfSastFailed;
        this.failIfSastUnstable = failIfSastUnstable;
        this.verbose = verbose;
        this.sastAgentNodeName = sastAgentNodeName;
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
            throw new RuntimeException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.exception_failedToGetEnvVars(), e);
        }
    }

    protected void verboseLog(TaskListener listener, String format, Object... args) {
        if (!this.verbose) return;
        log(listener, format, args);
    }

    protected void log(TaskListener listener, String format, Object... args) {
        listener.getLogger().print(consolePrefix + String.format(format, args));
    }

    @Override
    public void perform(@Nonnull Run<?, ?> build, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener) throws InterruptedException, IOException {
        Jenkins jenkins = Jenkins.get();
        final BuildEnv currentBuildEnv = new BuildEnv(getEnvironmentVariables(build, listener), workspace, build.getTimestamp());
        final BuildEnv targetBuildEnv = null;
        final BuildInfo buildInfo = new BuildInfo(currentBuildEnv, targetBuildEnv);
        buildInfo.setEffectiveEnvironmentInBuildInfo();

        PtaiSastConfig cfg = getDescriptor().getSastConfig(sastConfigName);
        if (StringUtils.isEmpty(cfg.getSastConfigPtaiHostUrl()))
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_emptyPtaiHostUrl());
        if (StringUtils.isEmpty(cfg.getSastConfigPtaiCert()))
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_emptyPtaiCert());
        if (StringUtils.isEmpty(cfg.getSastConfigPtaiCertPwd()))
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_emptyPtaiCertPwd());
        if (StringUtils.isEmpty(cfg.getSastConfigCaCerts()))
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_emptyPtaiCaCerts());

        PtaiProject ptaiProject = new PtaiProject();
        ptaiProject.setVerbose(this.verbose);
        ptaiProject.setConsoleLog(listener.getLogger());
        ptaiProject.setLogPrefix(this.consolePrefix);
        ptaiProject.setUrl(cfg.getSastConfigPtaiHostUrl());
        ptaiProject.setKeyPem(cfg.getSastConfigPtaiCert());
        ptaiProject.setKeyPassword(cfg.getSastConfigPtaiCertPwd());
        ptaiProject.setCaCertsPem(cfg.getSastConfigCaCerts());

        // Connect to PT AI server
        try {
            // Try to authenticate
            String ptaiToken = ptaiProject.init();
            if (StringUtils.isEmpty(ptaiToken))
                throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedPtaiServerAuth());
            verboseLog(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_successPtaiAuthToken(ptaiToken.substring(0, 10)) + "\r\n");

            // Search for project
            String uiPrj = Util.replaceMacro(this.uiProject, buildInfo.getEnvVars());
            uiPrj = Util.fixEmptyAndTrim(uiPrj);
            ptaiProject.setName(uiPrj);
            UUID projectId = ptaiProject.searchProject();
            if (null == projectId)
                throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedPtaiProjectByName());
            verboseLog(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_successPtaiProjectByName(projectId.toString().substring(0, 4)) + "\r\n");
            Transfers transfers = new Transfers();
            for (PtaiTransfer transfer : this.transfers)
                transfers.addTransfer(Transfer.builder()
                        .excludes(Util.replaceMacro(transfer.getExcludes(), buildInfo.getEnvVars()))
                        .flatten(transfer.isFlatten())
                        .includes(Util.replaceMacro(transfer.getIncludes(), buildInfo.getEnvVars()))
                        .patternSeparator(transfer.getPatternSeparator())
                        .removePrefix(Util.replaceMacro(transfer.getRemovePrefix(), buildInfo.getEnvVars()))
                        .build());


            // Upload project sources
            ptaiProject.upload(transfers, workspace.getRemote());
            // Let's start analysis
            SastJob sastJob = new SastJob();
            sastJob.setVerbose(verbose);
            sastJob.setConsoleLog(listener.getLogger());
            sastJob.setLogPrefix(this.consolePrefix);
            sastJob.setUrl(cfg.getSastConfigJenkinsHostUrl());
            sastJob.setJobName(cfg.getSastConfigJenkinsJobName());
            sastJob.setCaCertsPem(cfg.getSastConfigCaCerts());
            sastJob.setProjectName(ptaiProject.getName());
            sastJob.setNodeName(this.sastAgentNodeName);
            // Set authentication parameters
            Auth jenkinsAuth = cfg.getSastConfigJenkinsAuth();
            if (null == jenkinsAuth)
                throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedJenkinsAuthNotSet());
            if (jenkinsAuth instanceof CredentialsAuth) {
                Item item = jenkins.getItem("/");
                CredentialsAuth auth = (CredentialsAuth)jenkinsAuth;
                sastJob.setUserName(auth.getUserName(item));
                sastJob.setPassword(auth.getPassword(item));
            } else if (jenkinsAuth instanceof TokenAuth) {
                // Jenkins API tone authentication is not the same as JWT (i.e. "bearer" one)
                // It is just another form of login/password authentication
                TokenAuth auth = (TokenAuth)jenkinsAuth;
                sastJob.setUserName(auth.getUserName());
                sastJob.setPassword(auth.getApiToken());
            }
            sastJob.init();
            PtaiResultStatus sastJobRes = sastJob.execute(workspace.getRemote());

            if (failIfSastFailed && PtaiResultStatus.FAILURE.equals(sastJobRes))
                throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastFailed());
            if (failIfSastUnstable && PtaiResultStatus.UNSTABLE.equals(sastJobRes))
                throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.plugin_resultSastUnstable());
        } catch (JenkinsClientException e) {
            log(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedJenkinsApiDetails(e) + "\r\n");
            throw new AbortException(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failed());
        } catch (PtaiClientException e) {
            log(listener, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_failedPtaiApiDetails(e) + "\r\n");
            throw new AbortException(Messages.validator_failed());
        }
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

    protected static String getCurrentItem(Run<?, ?> run, String currentItem){
        String runItem = null;
        String curItem = trimToNull(currentItem);
        if(run != null && run.getParent() != null)
            runItem = trimToNull(run.getParent().getFullName());

        if(runItem != null && curItem != null) {
            if(runItem.equals(curItem)) {
                return runItem;
            } else {
                throw new IllegalArgumentException(String.format("Current Item ('%s') and Parent Item from Run ('%s') differ!", curItem, runItem));
            }
        } else if(runItem != null) {
            return runItem;
        } else if(curItem != null) {
            return curItem;
        } else {
            throw new IllegalArgumentException("Both null, Run and Current Item!");
        }
    }
}