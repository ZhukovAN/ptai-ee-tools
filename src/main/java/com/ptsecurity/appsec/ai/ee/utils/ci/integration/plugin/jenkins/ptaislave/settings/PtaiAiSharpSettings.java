package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.List;

public class PtaiAiSharpSettings extends PtaiAiSettings {
    @Getter
    private PtaiSharpProjectType projectType;

    @Getter
    private boolean useEntryPoints;

    @Getter
    private boolean usePublicProtected;

    @Getter
    private OptionalStringParameter useCustomSastRules;

    @Getter
    private boolean downloadDependencies;

    @DataBoundConstructor
    public PtaiAiSharpSettings(final PtaiSharpProjectType projectType,
                               final boolean useEntryPoints,
                               final boolean usePublicProtected,
                               final OptionalStringParameter useCustomSastRules,
                               final boolean downloadDependencies) {
        this.projectType = projectType;
        this.useEntryPoints = useEntryPoints;
        this.usePublicProtected = usePublicProtected;
        this.useCustomSastRules = useCustomSastRules;
        this.downloadDependencies = downloadDependencies;
    }

    @Extension
    public static class PtaiAiSharpSettingsDescriptor extends PtaiAiSettingsDescriptor {
        @Override
        public String getDisplayName() {
            return ".NET (C#, Visual basic)";
        }

        public static List<PtaiSharpProjectType.PtaiSharpProjectTypeDescriptor> getSharpProjectTypeDescriptors() {
            return PtaiSharpProjectType.getAll();
        }


    }

}
