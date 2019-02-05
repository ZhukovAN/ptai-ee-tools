package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.util.ComboBoxModel;
import hudson.util.ListBoxModel;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

public class PtaiUiBasedJobSettings extends PtaiJobSettings {
    @Extension
    public static final PtaiJobSettingsDescriptor DESCRIPTOR = new PtaiUiBasedJobSettingsDescriptor();

    @Getter
    private String uiProjectName;

    @Getter
    private PtaiUiProject uiProject;

    @DataBoundConstructor
    public PtaiUiBasedJobSettings(
            final String uiProjectName,
            final PtaiUiProject uiProject) {
        this.uiProjectName = uiProjectName;
        this.uiProject = uiProject;
    }

    @Override
    public PtaiJobSettingsDescriptor getDescriptor() {
        return DESCRIPTOR;
    }

    public static class PtaiUiBasedJobSettingsDescriptor extends PtaiJobSettingsDescriptor {
        @Override
        public String getDisplayName() {
            return "UI-based job settings";
        }

        public ListBoxModel doFillUiProjectItems(@QueryParameter String sastConfigName1) {
            ListBoxModel m = new ListBoxModel();
            m.add(sastConfigName1 + " 1", sastConfigName1 + " 1");
            m.add(sastConfigName1 + " 2", sastConfigName1 + " 2");
            m.add(sastConfigName1 + " 3", sastConfigName1 + " 3");
            m.add(sastConfigName1 + " 4", sastConfigName1 + " 4");
            return m;
        }
    }
}
