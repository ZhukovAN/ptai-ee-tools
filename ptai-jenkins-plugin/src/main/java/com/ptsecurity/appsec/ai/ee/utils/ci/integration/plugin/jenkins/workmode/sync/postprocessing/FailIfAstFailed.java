package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.sync.postprocessing;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync;
import hudson.Extension;
import hudson.util.ListBoxModel;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class FailIfAstFailed extends BasePostProcessingStep {
    @Getter
    private final WorkModeSync.OnAstError onAstFailed;

    @DataBoundConstructor
    public FailIfAstFailed(final WorkModeSync.OnAstError onAstFailed) {
        this.onAstFailed = onAstFailed;
    }

    @Symbol("FailIfAstFailed")
    @Extension
    public static class FailIfAstFailedDescriptor extends BasePostProcessingStepDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_processpolicy_label();
        }

        public ListBoxModel doFillOnAstFailedItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_processerrors_action_values_fail(), WorkModeSync.OnAstError.FAIL.name());
            model.add(Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_processerrors_action_values_unstable(), WorkModeSync.OnAstError.UNSTABLE.name());
            return model;
        }

        public static WorkModeSync.OnAstError getDefaultOnAstFailed() {
            return WorkModeSync.OnAstError.FAIL;
        }
    }
}
