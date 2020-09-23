package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.Report;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.Report.ReportDescriptor;
import hudson.Extension;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.jetbrains.annotations.NotNull;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.ArrayList;

public class WorkModeSync extends WorkMode {
    @Extension
    public static final WorkModeDescriptor DESCRIPTOR = new Descriptor();

    @Getter
    private final boolean failIfFailed;

    @Getter
    private final boolean failIfUnstable;

    @Getter
    private ArrayList<Report> reports;

    public final void setReports(final ArrayList<Report> reports) {
        if (reports == null)
            this.reports = new ArrayList<>();
        else
            this.reports = reports;
    }

    @DataBoundConstructor
    public WorkModeSync(
            final boolean failIfFailed, final boolean failIfUnstable, final ArrayList<Report> reports) {
        this.failIfFailed = failIfFailed;
        this.failIfUnstable = failIfUnstable;
        setReports(reports);
    }

    @Symbol("WorkModeSync")
    public static class Descriptor extends WorkModeDescriptor {
        @NotNull
        @Override
        public String getDisplayName() {
            return Messages.captions_workMode_sync_displayName();
        }

        public ReportDescriptor getReportDescriptor() {
            return Jenkins.get().getDescriptorByType(ReportDescriptor.class);
        }
    }

}
