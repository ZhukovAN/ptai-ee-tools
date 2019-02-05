package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

public class PtaiAiJavaSettings extends PtaiAiSettings {
    @Getter
    private boolean useEntryPoints;

    @Getter
    private boolean usePublicProtected;

    @Getter
    private OptionalStringParameter useCustomSastRules;

    @Getter
    private boolean unpackUserPackages;

    @Getter
    private boolean downloadDependencies;

    @Getter
    private String javaLaunchOptions;

    @Getter
    private String jdkVersion;

    @Getter
    OptionalStringParameter useVersionDetectionPattern;

    @DataBoundConstructor
    public PtaiAiJavaSettings(final boolean useEntryPoints,
                              final boolean usePublicProtected,
                              final OptionalStringParameter useCustomSastRules,
                              final boolean unpackUserPackages,
                              final boolean downloadDependencies,
                              final String javaLaunchOptions,
                              final String jdkVersion,
                              final OptionalStringParameter useVersionDetectionPattern) {
        this.useEntryPoints = useEntryPoints;
        this.usePublicProtected = usePublicProtected;
        this.useCustomSastRules = useCustomSastRules;
        this.unpackUserPackages = unpackUserPackages;
        this.downloadDependencies = downloadDependencies;
        this.javaLaunchOptions = javaLaunchOptions;
        this.jdkVersion = jdkVersion;
        this.useVersionDetectionPattern = useVersionDetectionPattern;
    }

    @Extension
    public static class PtaiAiJavaSettingsDescriptor extends PtaiAiSettingsDescriptor {
        @Override
        public String getDisplayName() {
            return "Java";
        }
    }
}
