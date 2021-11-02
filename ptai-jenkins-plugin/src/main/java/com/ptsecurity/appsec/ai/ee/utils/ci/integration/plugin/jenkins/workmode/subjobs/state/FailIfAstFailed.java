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
public class FailIfAstFailed extends Base {

    @RequiredArgsConstructor
    private static class SubJob extends com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed {
        @NonNull
        private final FailIfAstFailed subJob;

        @Override
        public void execute(@NonNull final ScanBrief scanBrief) throws GenericException {
            try {
                super.execute(scanBrief);
            } catch (GenericException e) {
                JenkinsAstJob job = (JenkinsAstJob) owner;
                job.getRun().setResult(UNSTABLE == subJob.getOnAstFailed() ? Result.UNSTABLE : Result.FAILURE);
            }
        }
    }
    @Getter
    private final WorkModeSync.OnAstError onAstFailed;

    @DataBoundConstructor
    public FailIfAstFailed(final WorkModeSync.OnAstError onAstFailed) {
        this.onAstFailed = onAstFailed;
    }

    @Override
    public void apply(@NonNull JenkinsAstJob job) {
        new SubJob(this).attach(job);
    }

    @Extension
    @Symbol("failIfAstFailed")
    public static class FailIfAstFailedDescriptor extends BaseDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_subjob_state_processpolicy_label();
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillOnAstFailedItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Resources.i18n_ast_settings_mode_synchronous_subjob_state_processpolicy_action_values_fail(), WorkModeSync.OnAstError.FAIL.name());
            model.add(Resources.i18n_ast_settings_mode_synchronous_subjob_state_processpolicy_action_values_unstable(), UNSTABLE.name());
            return model;
        }

        @SuppressWarnings("unused")
        public static WorkModeSync.OnAstError getDefaultOnAstFailed() {
            return WorkModeSync.OnAstError.FAIL;
        }
    }
}
