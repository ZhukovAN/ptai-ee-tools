package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import hudson.Extension;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

@ToString
public class SonarGiif extends Export {
    @Getter
    private final String fileName;

    @Getter
    private final String filter;

    @DataBoundConstructor
    public SonarGiif(final String fileName, final String filter) {
        this.fileName = fileName;
        this.filter = filter;
    }

    @Override
    public void apply(@NonNull JenkinsAstJob job) {
        String fileName = job.replaceMacro(this.fileName);
        String filter = job.replaceMacro(this.filter);
        Reports.SonarGiif sonarGiif = Reports.SonarGiif.builder()
                .fileName(fileName)
                .filters(StringUtils.isNotEmpty(filter) ? ReportUtils.validateJsonFilter(filter) : null)
                .build();
        new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.SonarGiif(sonarGiif).attach(job);
    }

    @Extension
    @Symbol("sonarGiif")
    @SuppressWarnings("unused")
    public static class SonarGiifDescriptor extends ExportDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_label();
        }
    }
}
