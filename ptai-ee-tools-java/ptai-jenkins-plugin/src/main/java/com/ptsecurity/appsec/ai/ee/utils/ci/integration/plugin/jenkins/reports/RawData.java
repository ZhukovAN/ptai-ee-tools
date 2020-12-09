package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Messages;
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
            return Messages.i18n_reporting_rawdata_caption();
        }
    }
}
