package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class PtaiBlackBoxSettings extends AbstractDescribableImpl<PtaiBlackBoxSettings> implements Cloneable, Serializable {
    @DataBoundConstructor
    public PtaiBlackBoxSettings() {
    }

    @Extension
    public static class PtaiPmSettingsDescriptor extends Descriptor<PtaiBlackBoxSettings> {
        @Override
        public String getDisplayName() {
            return "PtaiBlackBoxSettingsDescriptor";
        }
    }
}
