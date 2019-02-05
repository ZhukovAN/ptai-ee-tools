package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.defaults;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils.FileFinder;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;

import java.io.Serializable;

public class PtaiTransferDefaults implements Describable<PtaiTransferDefaults>, Cloneable, Serializable {
    @Override
    public PtaiTransferDefaults.PtaiPluginDefaultsDescriptor getDescriptor() {
        return Jenkins.getInstance().getDescriptorByType(PtaiTransferDefaults.PtaiPluginDefaultsDescriptor.class);
    }

    @Extension
    public static final class PtaiPluginDefaultsDescriptor extends Descriptor<PtaiTransferDefaults> {

        @Override
        public String getDisplayName() {
            return ""; // Messages.defaults_pluginDefaults();
        }

    }

    public String getIncludes() {
        return null;
    }

    public String getRemovePrefix() {
        return null;
    }

    public String getExcludes() {
        return null;
    }

    public boolean isFlatten() {
        return false;
    }

    public boolean isUseDefaultExcludes() {
        return true;
    }

    public String getPatternSeparator() {
        return FileFinder.DEFAULT_PATTERN_SEPARATOR;
    }

}
