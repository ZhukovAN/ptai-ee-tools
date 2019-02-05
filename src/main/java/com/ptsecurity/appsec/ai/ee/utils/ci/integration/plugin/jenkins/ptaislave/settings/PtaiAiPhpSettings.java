package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

public class PtaiAiPhpSettings extends PtaiAiSettings {
    @Getter
    private boolean useEntryPoints;

    @Getter
    private boolean usePublicProtected;

    @Getter
    private OptionalStringParameter useCustomSastRules;

    @Getter
    private boolean downloadDependencies;

    @DataBoundConstructor
    public PtaiAiPhpSettings(final boolean useEntryPoints,
                             final boolean usePublicProtected,
                             final OptionalStringParameter useCustomSastRules,
                             final boolean downloadDependencies) {
        this.useEntryPoints = useEntryPoints;
        this.usePublicProtected = usePublicProtected;
        this.useCustomSastRules = useCustomSastRules;
        this.downloadDependencies = downloadDependencies;
    }

    @Extension
    public static class PtaiAiPhpSettingsDescriptor extends PtaiAiSettingsDescriptor {
        @Override
        public String getDisplayName() {
            return "PHP";
        }
    }

}
