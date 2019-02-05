package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastTemplate;
import hudson.Extension;
import hudson.model.Descriptor;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import java.util.List;

@Extension
public class PtaiSastTemplateDescriptor extends Descriptor<PtaiSastTemplate> {
    public PtaiSastTemplateDescriptor() {
        super(PtaiSastTemplate.class);
    }

    @Override
    public String getDisplayName() {
        return "PtaiSastTemplateDescriptor"; //Messages.hostconfig_descriptor();
    }

    /*
    public static List<BaseSettings.BaseSettingsDescriptor> getLanguageDescriptors() {
        return BaseSettings.getAll();
    }
    */
    /*
    public static BaseSettings.BaseSettingsDescriptor getDefaultLanguageDescriptor() {
        return JavaSettings.DESCRIPTOR;
    }
    */
}
