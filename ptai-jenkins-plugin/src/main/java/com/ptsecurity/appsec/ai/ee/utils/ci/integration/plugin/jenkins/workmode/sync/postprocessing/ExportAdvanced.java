package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.sync.postprocessing;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import hudson.Extension;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class ExportAdvanced extends BaseReportStep {
    @Getter
    private final String json;

    @DataBoundConstructor
    public ExportAdvanced(final String json) {
        this.json = json;
    }

    @Symbol("Json")
    @Extension
    public static class JsonDescriptor extends BaseReportDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_exportadvanced_label();
        }
    }
}
