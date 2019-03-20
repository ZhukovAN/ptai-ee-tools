package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PtaiTransferDescriptor;
import hudson.model.Describable;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

@EqualsAndHashCode
@ToString
public class PtaiTransfer implements Describable<PtaiTransfer>, Cloneable, Serializable {
    @Getter
    private final String remoteDirectory;
    @Getter
    private final String includes;
    @Getter
    private final String removePrefix;
    @Getter
    private final String excludes;
    @Getter
    private final String patternSeparator;
    @Getter
    private final boolean useDefaultExcludes;
    @Getter
    private final boolean flatten;

    @DataBoundConstructor
    public PtaiTransfer(final String includes, final String excludes, final String remoteDirectory, final String removePrefix,
                          final boolean flatten,
                          final boolean useDefaultExcludes, final String patternSeparator) {
        this.includes = includes;
        this.excludes = excludes;
        this.remoteDirectory = remoteDirectory;
        this.removePrefix = removePrefix;
        this.flatten = flatten;
        this.useDefaultExcludes = useDefaultExcludes;
        this.patternSeparator = patternSeparator;
    }

    public PtaiTransferDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(PtaiTransferDescriptor.class);
    }
}
