package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.Base;
import hudson.Extension;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.ArrayList;

@ToString
public class WorkModeSync extends WorkMode {
    public enum OnAstError {
        NONE, FAIL, UNSTABLE
    }
    @Extension
    public static final WorkModeDescriptor DESCRIPTOR = new Descriptor();

    @Getter
    private ArrayList<Base> subJobs;

    public final void setSubJobs(final ArrayList<Base> subJobs) {
        if (subJobs == null)
            this.subJobs = new ArrayList<>();
        else
            this.subJobs = subJobs;
    }

    @DataBoundConstructor
    public WorkModeSync(final ArrayList<Base> afterSteps) {
        setSubJobs(afterSteps);
    }

    @Symbol("WorkModeSync")
    public static class Descriptor extends WorkModeDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_label();
        }
    }

}
