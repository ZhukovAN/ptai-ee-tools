package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class ConfigBase extends AbstractDescribableImpl<ConfigBase> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<ConfigBase, ConfigBaseDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), ConfigBase.class);

    public static abstract class ConfigBaseDescriptor extends Descriptor<ConfigBase> {}
}
