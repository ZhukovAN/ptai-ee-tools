package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations.JenkinsAstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.operations.JenkinsFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.BaseReport;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.BuildInfo;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkMode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.util.List;

@Getter
@Setter
@SuperBuilder
@ToString(callSuper = true)
public class JenkinsAstJob extends AstJob {
    /**
     * CI workspace folder
     */
    @NonNull
    protected FilePath workspace;

    /**
     * Jenkins launcher that is used for function call on a
     * remote scan agent. As build task may be executed on
     * a remote agent, we need to take special care for
     * resource-consuming operations such as source code
     * archive creation and reports save to workspace
     */
    @NonNull
    @ToString.Exclude
    protected Launcher launcher;

    /**
     * Listener allow us to send log messages from remote
     * scan agent to Jenkins server
     */
    @NonNull
    @ToString.Exclude
    protected TaskListener listener;

    /**
     * Build info contains environment variables that may
     * be used for macro replacement
     */
    @NonNull
    protected BuildInfo buildInfo;

    /**
     * List of transfers, i.e. source files to be zipped
     * and sent to PT AI server
     */
    private List<Transfer> transfers;

    /**
     * Jenkins job work mode
     */
    private WorkMode workMode;

    @Override
    public boolean unsafeInit() {
        if (workMode instanceof WorkModeSync) {
            WorkModeSync workModeSync = (WorkModeSync) workMode;
            List<BaseReport> reports = workModeSync.getReports();
            if (null != reports) setReports(BaseReport.convert(reports));
        }
        astOps = JenkinsAstOperations.builder()
                .owner(this)
                .build();
        fileOps = JenkinsFileOperations.builder()
                .owner(this)
                .build();
        return super.unsafeInit();
    }
}
