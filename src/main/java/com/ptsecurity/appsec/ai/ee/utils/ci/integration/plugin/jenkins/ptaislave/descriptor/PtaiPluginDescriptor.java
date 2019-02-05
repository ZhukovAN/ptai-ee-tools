package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiPlugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastTemplate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings.PtaiJobSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.settings.PtaiUiBasedJobSettings;
import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.ComboBoxModel;
import hudson.util.CopyOnWriteList;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import java.util.List;

@Extension
public class PtaiPluginDescriptor extends BuildStepDescriptor<Builder> {

    private final CopyOnWriteList<PtaiSastConfig> sastConfigs = new CopyOnWriteList<PtaiSastConfig>();

    public List<PtaiSastConfig> getSastConfigs() {
        return sastConfigs.getView();
    }

    public PtaiSastConfigDescriptor getSastConfigDescriptor() {
        return Jenkins.getInstance().getDescriptorByType(PtaiSastConfigDescriptor.class);
    }

    private final CopyOnWriteList<PtaiSastTemplate> sastTemplates = new CopyOnWriteList<PtaiSastTemplate>();

    public List<PtaiSastTemplate> getSastTemplates() {
        return sastTemplates.getView();
    }

    public PtaiSastTemplateDescriptor getSastTemplateDescriptor() {
        return Jenkins.getInstance().getDescriptorByType(PtaiSastTemplateDescriptor.class);
    }

    public PtaiTransferDescriptor getTransferDescriptor() {
        return Jenkins.getInstance().getDescriptorByType(PtaiTransferDescriptor.class);
    }

    public PtaiPluginDescriptor() {
        super(PtaiPlugin.class);
        load();
    }

    @Override
    public boolean isApplicable(Class<? extends AbstractProject> jobType) {
        return true;
    }

    public PtaiSastConfig getSastConfig(final String configName) {
        for (PtaiSastConfig l_objCfg : sastConfigs) {
            if (l_objCfg.getSastConfigName().equals(configName))
                return l_objCfg;
        }
        return null;
    }

    public PtaiSastTemplate getSastTemplate(final String templateName) {
        for (PtaiSastTemplate l_objTemplate : sastTemplates) {
            if (l_objTemplate.getTemplateName().equals(templateName))
                return l_objTemplate;
        }
        return null;
    }

    public static List<PtaiJobSettings.PtaiJobSettingsDescriptor> getJobSettingsDescriptors() {
        return PtaiJobSettings.getAll();
    }

    public static PtaiJobSettings.PtaiJobSettingsDescriptor getDefaultJobSettingsDescriptor() {
        return PtaiUiBasedJobSettings.DESCRIPTOR;
    }

    public ListBoxModel doFillSastConfigNameItems() {
        ListBoxModel model = new ListBoxModel();
        for (PtaiSastConfig cfg : sastConfigs)
            model.add(cfg.getSastConfigName(), cfg.getSastConfigName());
        return model;
    }
    /*
    public ComboBoxModel doFillUiProjectItems(@QueryParameter String sastConfigName) {
        ComboBoxModel m = new ComboBoxModel();
        m.add(sastConfigName + " 1");
        m.add(sastConfigName + " 2");
        m.add(sastConfigName + " 3");
        m.add(sastConfigName + " 4");
        return m;
    }
*/
    public ListBoxModel doFillUiProjectItems(@QueryParameter String sastConfigName) {
        ListBoxModel m = new ListBoxModel();
        m.add(sastConfigName + " 1", sastConfigName + " 1");
        m.add(sastConfigName + " 2", sastConfigName + " 2");
        m.add(sastConfigName + " 3", sastConfigName + " 3");
        m.add(sastConfigName + " 4", sastConfigName + " 4");
        return m;
    }

    @Override
    public boolean configure(StaplerRequest theRq, JSONObject theFormData) throws FormException {
        theFormData = theFormData.getJSONObject("ptai");
        sastConfigs.replaceBy(theRq.bindJSONToList(PtaiSastConfig.class, theFormData.get("instanceConfig")));
        sastTemplates.replaceBy(theRq.bindJSONToList(PtaiSastTemplate.class, theFormData.get("instanceTemplate")));
        save();
        return true;
    }

    public String getDisplayName() {
        return "PT AI SAST";
    }
}
