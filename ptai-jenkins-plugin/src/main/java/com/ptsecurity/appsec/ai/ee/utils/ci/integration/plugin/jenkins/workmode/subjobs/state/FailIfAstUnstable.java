package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.state;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.Base;
import hudson.Extension;
import hudson.model.Result;
import hudson.util.ListBoxModel;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync.OnAstError.UNSTABLE;

@ToString
public class FailIfAstUnstable extends Base {
    @RequiredArgsConstructor
    private static class SubJob extends com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstUnstable {
        @NonNull
        private final FailIfAstUnstable subJob;

        @Override
        public void execute(@NonNull final ScanBrief scanBrief) throws GenericException {
            try {
                super.execute(scanBrief);
            } catch (GenericException e) {
                JenkinsAstJob job = (JenkinsAstJob) owner;
                job.getRun().setResult(UNSTABLE == subJob.getOnAstUnstable() ? Result.UNSTABLE : Result.FAILURE);
            }
        }
    }
    @Getter
    private final WorkModeSync.OnAstError onAstUnstable;

    @DataBoundConstructor
    public FailIfAstUnstable(final WorkModeSync.OnAstError onAstUnstable) {
        this.onAstUnstable = onAstUnstable;
    }

    @Override
    public void apply(@NonNull JenkinsAstJob job) {
        new FailIfAstUnstable.SubJob(this).attach(job);
    }

    @Extension
    @Symbol("failIfAstUnstable")
    public static class FailIfAstUnstableDescriptor extends BaseDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_subjob_state_processerrors_label();
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillOnAstUnstableItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Resources.i18n_ast_settings_mode_synchronous_subjob_state_processerrors_action_values_fail(), WorkModeSync.OnAstError.FAIL.name());
            model.add(Resources.i18n_ast_settings_mode_synchronous_subjob_state_processerrors_action_values_unstable(), WorkModeSync.OnAstError.UNSTABLE.name());
            return model;
        }

        @SuppressWarnings("unused")
        public static WorkModeSync.OnAstError getDefaultOnAstUnstable() {
            return WorkModeSync.OnAstError.UNSTABLE;
        }
    }
}
