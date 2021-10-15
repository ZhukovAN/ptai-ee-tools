package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.sync.postprocessing;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import hudson.Extension;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class ExportRaw extends BaseReportStep {
    @Getter
    private final String fileName;

    @DataBoundConstructor
    public ExportRaw(final String fileName) {
        this.fileName = fileName;
    }

    @Symbol("RawData")
    @Extension
    public static class RawDataDescriptor extends BaseReportDescriptor {
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_exportraw_label();
        }
    }
}
