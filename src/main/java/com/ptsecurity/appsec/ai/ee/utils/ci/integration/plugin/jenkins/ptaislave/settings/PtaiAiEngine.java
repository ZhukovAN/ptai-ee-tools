package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class PtaiAiEngine extends AbstractDescribableImpl<PtaiAiEngine> implements Serializable, Cloneable {
    @Getter
    private PtaiAiSettings aiEngineSettings;

    @DataBoundConstructor
    public PtaiAiEngine(final PtaiAiSettings aiEngineSettings) {
        this.aiEngineSettings = aiEngineSettings;
    }

    @Extension
    public static class PtaiAiEngineDescriptor extends Descriptor<PtaiAiEngine> {
        @Override
        public String getDisplayName() {
            return "Optional";
        }
    }
}
