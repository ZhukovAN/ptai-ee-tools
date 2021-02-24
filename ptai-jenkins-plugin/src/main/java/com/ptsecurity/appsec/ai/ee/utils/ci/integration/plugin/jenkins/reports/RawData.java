package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import hudson.Extension;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class RawData extends BaseReport {
    @Getter
    private final String fileName;

    @DataBoundConstructor
    public RawData(final String fileName) {
        this.fileName = fileName;
    }

    @Symbol("RawData")
    @Extension
    public static class RawDataDescriptor extends BaseReportDescriptor {
        @Override
        public String getDisplayName() {
            return Resources.i18n_ast_result_reporting_rawdata_label();
        }
    }
}
