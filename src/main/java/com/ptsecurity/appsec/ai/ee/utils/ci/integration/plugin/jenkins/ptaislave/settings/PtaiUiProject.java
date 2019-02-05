package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;
import java.util.List;

public class PtaiUiProject implements Describable<PtaiUiProject>, Cloneable, Serializable {
    @Getter
    private String id;
    @Getter
    private String name;

    @DataBoundConstructor
    public PtaiUiProject(final String id, final String name) {
        this.id = id;
        this.name = name;
    }

    public PtaiUiProjectDescriptor getDescriptor() {
        return Jenkins.getInstance().getDescriptorByType(PtaiUiProjectDescriptor.class);
    }

    @Extension
    public static class PtaiUiProjectDescriptor extends Descriptor<PtaiUiProject> {
        @Override
        public String getDisplayName() {
            return "PTAI UI project";
        }
    }
}
