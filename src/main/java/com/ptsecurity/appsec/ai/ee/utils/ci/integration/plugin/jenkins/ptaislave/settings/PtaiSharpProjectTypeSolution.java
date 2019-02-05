package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastTemplate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor.PtaiPluginDescriptor;
import hudson.Extension;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.List;

public class PtaiSharpProjectTypeSolution extends PtaiSharpProjectType {
    @Getter
    private String solutionFilePath;

    @DataBoundConstructor
    public PtaiSharpProjectTypeSolution(final String solutionFilePath) {
        this.solutionFilePath = solutionFilePath;
    }

    @Extension
    public static class PtaiSharpProjectTypeSolutionDescriptor extends PtaiSharpProjectTypeDescriptor {
        @Override
        public String getDisplayName() {
            return "Solution/Project";
        }
    }
}
