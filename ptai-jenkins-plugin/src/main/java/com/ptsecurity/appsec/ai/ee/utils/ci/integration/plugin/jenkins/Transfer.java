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
@ToString
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

    public TransferDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(TransferDescriptor.class);
    }
}
