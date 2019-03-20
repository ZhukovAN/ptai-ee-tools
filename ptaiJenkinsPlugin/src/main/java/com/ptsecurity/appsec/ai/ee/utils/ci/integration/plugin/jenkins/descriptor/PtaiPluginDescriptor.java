package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.exceptions.PtaiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.PtaiPlugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.PtaiSastConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.CopyOnWriteList;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.parboiled.common.StringUtils;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Extension
@Symbol("ptaiUiSast")
public class PtaiPluginDescriptor extends BuildStepDescriptor<Builder> {

    private final CopyOnWriteList<PtaiSastConfig> sastConfigs = new CopyOnWriteList<>();

    public List<PtaiSastConfig> getSastConfigs() {
        return sastConfigs.getView();
    }

    public PtaiSastConfigDescriptor getSastConfigDescriptor() {
        return Jenkins.get().getDescriptorByType(PtaiSastConfigDescriptor.class);
    }

    public PtaiTransferDescriptor getTransferDescriptor() {
        return Jenkins.get().getDescriptorByType(PtaiTransferDescriptor.class);
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
        for (PtaiSastConfig cfg : sastConfigs) {
            if (cfg.getSastConfigName().equals(configName))
                return cfg;
        }
        return null;
    }

    public ListBoxModel doFillSastConfigNameItems() {
        ListBoxModel model = new ListBoxModel();
        for (PtaiSastConfig cfg : sastConfigs)
            model.add(cfg.getSastConfigName(), cfg.getSastConfigName());
        return model;
    }

    @Override
    public boolean configure(StaplerRequest theRq, JSONObject theFormData) throws FormException {
        theFormData = theFormData.getJSONObject("ptai");
        sastConfigs.replaceBy(theRq.bindJSONToList(PtaiSastConfig.class, theFormData.get("instanceConfig")));
        save();
        return true;
    }

    public FormValidation doTestUiProject(
            @QueryParameter("sastConfigName") final String sastConfigName,
            @QueryParameter("uiProject") final String uiProject) throws IOException {
        try {
            if (StringUtils.isEmpty(sastConfigName))
                throw new PtaiException(Messages.validator_emptyConfigName());
            if (StringUtils.isEmpty(uiProject))
                throw new PtaiException(Messages.validator_emptyPtaiProjectName());
            PtaiSastConfig cfg = getSastConfig(sastConfigName);
            if (StringUtils.isEmpty(cfg.getSastConfigPtaiHostUrl()))
                throw new PtaiException(Messages.validator_emptyPtaiHostUrl());
            if (StringUtils.isEmpty(cfg.getSastConfigPtaiCert()))
                throw new PtaiException(Messages.validator_emptyPtaiCert());
            if (StringUtils.isEmpty(cfg.getSastConfigPtaiCertPwd()))
                throw new PtaiException(Messages.validator_emptyPtaiCertPwd());
            if (StringUtils.isEmpty(cfg.getSastConfigCaCerts()))
                throw new PtaiException(Messages.validator_emptyPtaiCaCerts());
            PtaiProject ptaiProject = new PtaiProject();
            ptaiProject.setUrl(cfg.getSastConfigPtaiHostUrl());
            ptaiProject.setKeyPem(cfg.getSastConfigPtaiCert());
            ptaiProject.setKeyPassword(cfg.getSastConfigPtaiCertPwd());
            ptaiProject.setCaCertsPem(cfg.getSastConfigCaCerts());

            // Connect to PT AI server
            // Try to authenticate
            String ptaiToken = ptaiProject.init();
            if (StringUtils.isEmpty(ptaiToken))
                return FormValidation.error(Messages.validator_failedPtaiServerAuth());
            // Search for project
            ptaiProject.setName(Util.fixEmptyAndTrim(uiProject));
            UUID projectId = ptaiProject.searchProject();
            if (null == projectId)
                return FormValidation.error(Messages.validator_failedPtaiProjectByName());
            return FormValidation.ok(Messages.validator_successPtaiProjectByName(projectId.toString().substring(0, 4)));
        } catch (PtaiClientException e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    public String getDisplayName() {
        return Messages.pluginStepName();
    }

    public FormValidation doCheckUiProject(@QueryParameter("uiProject") String uiProject) {
        return doCheckField(uiProject, Messages.validator_emptyPtaiProjectName());
    }

    protected FormValidation doCheckField(String value, String errorMessage) {
        if (null != Util.fixEmptyAndTrim(value))
            return FormValidation.ok();
        else
            return FormValidation.error(errorMessage);
    }


}
