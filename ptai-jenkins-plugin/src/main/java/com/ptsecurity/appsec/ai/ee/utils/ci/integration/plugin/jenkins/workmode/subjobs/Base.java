package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.JenkinsAstJob;
import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;
import lombok.NonNull;

import java.io.Serializable;

public abstract class Base extends AbstractDescribableImpl<Base> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<Base, BaseDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), Base.class);

    public static abstract class BaseDescriptor extends Descriptor<Base> {
    }

    @Override
    public Base clone() throws CloneNotSupportedException {
        return (Base) super.clone();
    }

    public abstract void apply(@NonNull final JenkinsAstJob job);
}
