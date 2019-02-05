package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

public class PtaiSharpProjectTypeWebSite extends PtaiSharpProjectType {
    @Getter
    private String solutionFilePath;

    @DataBoundConstructor
    public PtaiSharpProjectTypeWebSite(final String solutionFilePath) {
        this.solutionFilePath = solutionFilePath;
    }

    @Extension
    public static class PtaiSharpProjectTypeWebSiteDescriptor extends PtaiSharpProjectTypeDescriptor {
        @Override
        public String getDisplayName() {
            return "Web Site ASP.NET";
        }
    }
}
