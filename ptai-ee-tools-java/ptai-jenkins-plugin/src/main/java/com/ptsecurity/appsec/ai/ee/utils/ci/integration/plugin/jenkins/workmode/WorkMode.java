package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class WorkMode extends AbstractDescribableImpl<WorkMode> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<WorkMode, WorkModeDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), WorkMode.class);

    public static abstract class WorkModeDescriptor extends Descriptor<WorkMode> {}
}
