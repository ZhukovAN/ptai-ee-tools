package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import hudson.Extension;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
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
        new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson(rawData).attach(job);
    }

    @Extension
    @Symbol("rawJson")
    @SuppressWarnings("unused")
    public static class RawJsonDescriptor extends ExportDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_label();
        }
    }
}
