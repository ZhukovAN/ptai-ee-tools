package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class PtaiSharpProjectType extends AbstractDescribableImpl<PtaiSharpProjectType> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<PtaiSharpProjectType, PtaiSharpProjectTypeDescriptor> all = DescriptorExtensionList.createDescriptorList(Jenkins.getInstance(), PtaiSharpProjectType.class);

    public static abstract class PtaiSharpProjectTypeDescriptor extends Descriptor<PtaiSharpProjectType> {}

    @Override
    public PtaiAiSettings clone() throws CloneNotSupportedException {
        return (PtaiAiSettings)super.clone();
    };
}
