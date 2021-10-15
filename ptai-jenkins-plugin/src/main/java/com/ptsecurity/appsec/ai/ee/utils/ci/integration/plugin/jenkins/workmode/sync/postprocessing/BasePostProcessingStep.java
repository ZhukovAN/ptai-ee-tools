package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.sync.postprocessing;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class BasePostProcessingStep extends AbstractDescribableImpl<BasePostProcessingStep> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<BasePostProcessingStep, BasePostProcessingStepDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), BasePostProcessingStep.class);

    public static abstract class BasePostProcessingStepDescriptor extends Descriptor<BasePostProcessingStep> {
    }

    @Override
    public BasePostProcessingStep clone() throws CloneNotSupportedException {
        return (BasePostProcessingStep) super.clone();
    }
}
