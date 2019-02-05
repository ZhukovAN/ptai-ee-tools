package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;
import java.util.List;

public class PtaiSastSettings extends AbstractDescribableImpl<PtaiSastSettings> implements Cloneable, Serializable {
    @Getter
    private String siteAddress;
    @Getter
    private int threadsNumber;
    @Getter
    private String launchParameters;
    @Getter
    private int timeout;

    @Getter
    private PtaiAiEngine useAi;
    @Getter
    private PtaiScaSettings useSca;
    @Getter
    private PtaiPmSettings usePm;
    @Getter
    private PtaiCfgSettings useCfg;
    @Getter
    private PtaiBlackBoxSettings useBlackBox;

    @DataBoundConstructor
    public PtaiSastSettings(final String siteAddress, final int threadsNumber,
                            final String launchParameters, final int timeout,
                            final PtaiAiEngine useAi, final PtaiScaSettings useSca, final PtaiPmSettings usePm,
                            final PtaiCfgSettings useCfg, final PtaiBlackBoxSettings useBlackBox) {
        this.siteAddress = siteAddress;
        this.threadsNumber = threadsNumber;
        this.launchParameters = launchParameters;
        this.timeout = timeout;
        this.useAi = useAi;
        this.useSca = useSca;
        this.usePm = usePm;
        this.useCfg = useCfg;
        this.useBlackBox = useBlackBox;
    }

    @Extension
    public static class PtaiSastSettingsDescriptor extends Descriptor<PtaiSastSettings> {
        @Override
        public String getDisplayName() {
            return "PtaiSastSettingsDescriptor";
        }

        public static List<PtaiAiSettings.PtaiAiSettingsDescriptor> getAiSettingsDescriptors() {
            return PtaiAiSettings.getAll();
        }
/*
        public static Auth.AuthDescriptor getDefaultAuthDescriptor() {
            return NoneAuth.DESCRIPTOR;
        }*/

        public PtaiAiSettings.PtaiAiSettingsDescriptor getAiSettingsDescriptor() {
            return Jenkins.getInstance().getDescriptorByType(PtaiAiSettings.PtaiAiSettingsDescriptor.class);
        }

        public PtaiScaSettings.PtaiScaSettingsDescriptor getScaSettingsDescriptor() {
            return Jenkins.getInstance().getDescriptorByType(PtaiScaSettings.PtaiScaSettingsDescriptor.class);
        }

        public PtaiPmSettings.PtaiPmSettingsDescriptor getPmSettingsDescriptor() {
            return Jenkins.getInstance().getDescriptorByType(PtaiPmSettings.PtaiPmSettingsDescriptor.class);
        }
    }
}