package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class OptionalStringParameter extends AbstractDescribableImpl<OptionalStringParameter> implements Serializable, Cloneable {
    @Getter
    private String value;

    @DataBoundConstructor
    public OptionalStringParameter(final String value) {
        this.value = value;
    }

    @Extension
    public static class PtaiOptionalAiSettingsDescriptor extends Descriptor<OptionalStringParameter> {
        @Override
        public String getDisplayName() {
            return "OptionalStringParameter";
        }
    }

}

