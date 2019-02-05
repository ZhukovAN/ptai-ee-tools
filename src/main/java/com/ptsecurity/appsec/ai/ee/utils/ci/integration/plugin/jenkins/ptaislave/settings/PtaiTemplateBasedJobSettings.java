package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastTemplate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor.PtaiPluginDescriptor;
import hudson.Extension;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.List;

public class PtaiTemplateBasedJobSettings extends PtaiJobSettings {
    @Getter
    private String templateName;

    @DataBoundConstructor
    public PtaiTemplateBasedJobSettings(final String templateName) {
        this.templateName = templateName;
    }

    @Extension
    public static class PtaiTemplateBasedJobSettingsDescriptor extends PtaiJobSettingsDescriptor {
        @Override
        public String getDisplayName() {
            return "Template-based job settings";
        }

        public List<PtaiSastTemplate> getSastTemplates() {
            PtaiPluginDescriptor l_objDesc = Jenkins.getInstance().getDescriptorByType(PtaiPluginDescriptor.class);
            return l_objDesc.getSastTemplates();
        }
    }
}
