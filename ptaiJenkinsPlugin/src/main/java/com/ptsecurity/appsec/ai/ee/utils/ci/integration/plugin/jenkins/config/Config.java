package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.config;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class Config extends AbstractDescribableImpl<Config> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<Config, ConfigDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), Config.class);

    public static abstract class ConfigDescriptor extends Descriptor<Config> {}
}
