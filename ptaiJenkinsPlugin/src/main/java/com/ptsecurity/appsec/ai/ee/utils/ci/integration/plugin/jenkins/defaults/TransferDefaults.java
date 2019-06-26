package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.defaults;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;

public class TransferDefaults implements Describable<TransferDefaults> {
    public String getIncludes() {
        return null;
    }
    public String getRemovePrefix() { return null; }
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
        return Transfer.DEFAULT_PATTERN_SEPARATOR;
    }

    @Override
    public TransferDefaultsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(TransferDefaultsDescriptor.class);
    }

    @Extension
    public static final class TransferDefaultsDescriptor extends Descriptor<TransferDefaults> {
        @Override
        public String getDisplayName() {
            return "";
        }
    }
}
