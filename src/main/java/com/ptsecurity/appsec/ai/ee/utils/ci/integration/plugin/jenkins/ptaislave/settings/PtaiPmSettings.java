package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Describable;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class PtaiPmSettings extends AbstractDescribableImpl<PtaiPmSettings> implements Cloneable, Serializable {
    @DataBoundConstructor
    public PtaiPmSettings() {
    }

    @Extension
    public static class PtaiPmSettingsDescriptor extends Descriptor<PtaiPmSettings> {
        @Override
        public String getDisplayName() {
            return "PtaiPmSettingsDescriptor";
        }
    }
}
