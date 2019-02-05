package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.Auth;
import hudson.DescriptorExtensionList;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;

import java.io.Serializable;

public abstract class PtaiAiSettings extends AbstractDescribableImpl<PtaiAiSettings> implements Serializable, Cloneable {
    @Getter
    private static final DescriptorExtensionList<PtaiAiSettings, PtaiAiSettingsDescriptor> all = DescriptorExtensionList.createDescriptorList(Jenkins.getInstance(), PtaiAiSettings.class);

    public static abstract class PtaiAiSettingsDescriptor extends Descriptor<PtaiAiSettings> {}

    // public abstract void setAuthorizationHeader(URLConnection connection, BuildContext context) throws IOException;
    @Override
    public PtaiAiSettings clone() throws CloneNotSupportedException {
        return (PtaiAiSettings)super.clone();
    };
}
