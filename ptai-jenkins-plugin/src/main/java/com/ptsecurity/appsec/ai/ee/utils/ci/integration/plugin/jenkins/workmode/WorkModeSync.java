package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.BaseReport;
import hudson.Extension;
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
    private ArrayList<BaseReport> reports;

    public final void setReports(final ArrayList<BaseReport> reports) {
        if (reports == null)
            this.reports = new ArrayList<>();
        else
            this.reports = reports;
    }

    @DataBoundConstructor
    public WorkModeSync(
            final boolean failIfFailed, final boolean failIfUnstable, final ArrayList<BaseReport> reports) {
        this.failIfFailed = failIfFailed;
        this.failIfUnstable = failIfUnstable;
        setReports(reports);
    }

    @Symbol("WorkModeSync")
    public static class Descriptor extends WorkModeDescriptor {
        @NotNull
        @Override
        public String getDisplayName() {
            return Resources.captions_workMode_sync_displayName();
        }
    }

}
