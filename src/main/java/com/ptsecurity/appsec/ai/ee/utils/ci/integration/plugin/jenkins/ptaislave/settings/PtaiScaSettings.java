package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class PtaiScaSettings extends AbstractDescribableImpl<PtaiScaSettings> implements Cloneable, Serializable {
    @Getter
    private boolean usePtScaDatabase;
    /*
    @DataBoundConstructor
    public PtaiScaSettings(final boolean usePtScaDatabase) {
        this.usePtScaDatabase = usePtScaDatabase;
    }
    */
    @Getter
    private OptionalStringParameter useCustomYaraRules;

    @DataBoundConstructor
    public PtaiScaSettings(final boolean usePtScaDatabase, final OptionalStringParameter useCustomYaraRules) {
        this.usePtScaDatabase = usePtScaDatabase;
        this.useCustomYaraRules = useCustomYaraRules;
    }

    @Extension
    public static class PtaiScaSettingsDescriptor extends Descriptor<PtaiScaSettings> {
        @Override
        public String getDisplayName() {
            return "PtaiScaSettingsDescriptor";
        }
    }
}