package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

public class PtaiCustomJobSettings extends PtaiJobSettings {
    @Getter
    private PtaiSastSettings sastSettings;

    @DataBoundConstructor
    public PtaiCustomJobSettings(final PtaiSastSettings sastSettings) {
        this.sastSettings = sastSettings;
    }

    @Extension
    public static class PtaiCustomJobSettingsDescriptor extends PtaiJobSettingsDescriptor {
        @Override
        public String getDisplayName() {
            return "Custom job settings";
        }
    }
}
