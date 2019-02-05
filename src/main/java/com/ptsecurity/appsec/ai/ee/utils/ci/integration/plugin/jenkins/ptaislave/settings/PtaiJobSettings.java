package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class PtaiJobSettings extends AbstractDescribableImpl<PtaiJobSettings> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<PtaiJobSettings, PtaiJobSettingsDescriptor> all = DescriptorExtensionList.createDescriptorList(Jenkins.getInstance(), PtaiJobSettings.class);

    public static abstract class PtaiJobSettingsDescriptor extends Descriptor<PtaiJobSettings> {}

    @Override
    public PtaiAiSettings clone() throws CloneNotSupportedException {
        return (PtaiAiSettings)super.clone();
    };
}
