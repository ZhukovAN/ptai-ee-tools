package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.TransferDescriptor;
import hudson.model.Describable;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

@EqualsAndHashCode(callSuper = false)
@ToString(callSuper = true)
public class Transfer extends com.ptsecurity.appsec.ai.ee.scan.sources.Transfer implements Describable<Transfer>, Serializable {
    @DataBoundConstructor
    public Transfer(final String includes, final String excludes, final String removePrefix,
                    final boolean flatten,
                    final boolean useDefaultExcludes, final String patternSeparator) {
        this.includes = includes;
        this.excludes = excludes;
        this.removePrefix = removePrefix;
        this.flatten = flatten;
        this.useDefaultExcludes = useDefaultExcludes;
        this.patternSeparator = patternSeparator;
    }

    public Transfer() {
        this.includes = DEFAULT_INCLUDES;
        this.excludes = DEFAULT_EXCLUDES;
        this.removePrefix = DEFAULT_REMOVE_PREFIX;
        this.flatten = DEFAULT_FLATTEN;
        this.useDefaultExcludes = DEFAULT_USE_DEFAULT_EXCLUDES;
        this.patternSeparator = DEFAULT_PATTERN_SEPARATOR;
    }

    public TransferDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(TransferDescriptor.class);
    }
}
