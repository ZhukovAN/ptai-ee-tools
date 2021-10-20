package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import hudson.Extension;
import lombok.Getter;
import lombok.NonNull;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class RawJson extends Export {
    @Getter
    private final String fileName;

    @DataBoundConstructor
    public RawJson(final String fileName) {
        this.fileName = fileName;
    }

    @Override
    public void apply(@NonNull JenkinsAstJob job) {
        Reports.RawData rawData = Reports.RawData.builder()
                .fileName(fileName)
                .build();
        job.addSubJob(new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson(job, rawData));
    }

    @Symbol("RawJson")
    @Extension
    @SuppressWarnings("unused")
    public static class RawJsonDescriptor extends ExportDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_exportraw_label();
        }
    }
}
