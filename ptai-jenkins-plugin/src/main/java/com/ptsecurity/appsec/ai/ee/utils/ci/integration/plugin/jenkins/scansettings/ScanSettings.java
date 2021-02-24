package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings;

import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class ScanSettings extends AbstractDescribableImpl<ScanSettings> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<ScanSettings, ScanSettingsDescriptor> all =
            DescriptorExtensionList.createDescriptorList(Jenkins.get(), ScanSettings.class);

    public static abstract class ScanSettingsDescriptor extends Descriptor<ScanSettings> {}
}
