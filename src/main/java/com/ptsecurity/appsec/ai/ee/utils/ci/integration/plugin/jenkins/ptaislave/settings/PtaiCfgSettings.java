package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class PtaiCfgSettings extends AbstractDescribableImpl<PtaiCfgSettings> implements Cloneable, Serializable {
    @DataBoundConstructor
    public PtaiCfgSettings() {
    }

    @Extension
    public static class PtaiPmSettingsDescriptor extends Descriptor<PtaiCfgSettings> {
        @Override
        public String getDisplayName() {
            return "PtaiCfgSettingsDescriptor";
        }
    }
}
