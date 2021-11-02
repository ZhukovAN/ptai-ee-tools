package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.defaults;

import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.NonNull;
import org.jenkinsci.Symbol;

public class TransferDefaults implements Describable<TransferDefaults> {
    public String getIncludes() {
        return Transfer.DEFAULT_INCLUDES;
    }
    public String getRemovePrefix() { return Transfer.DEFAULT_REMOVE_PREFIX; }
    public String getExcludes() {
        return Transfer.DEFAULT_EXCLUDES;
    }
    public boolean isFlatten() { return Transfer.DEFAULT_FLATTEN; }
    public boolean isUseDefaultExcludes() {
        return Transfer.DEFAULT_USE_DEFAULT_EXCLUDES;
    }
    public String getPatternSeparator() {
        return Transfer.DEFAULT_PATTERN_SEPARATOR;
    }

    @Override
    public TransferDefaultsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(TransferDefaultsDescriptor.class);
    }

    @Extension
    @Symbol("transferDefaults")
    public static final class TransferDefaultsDescriptor extends Descriptor<TransferDefaults> {
        @Override
        @NonNull
        public String getDisplayName() {
            return "";
        }
    }
}
