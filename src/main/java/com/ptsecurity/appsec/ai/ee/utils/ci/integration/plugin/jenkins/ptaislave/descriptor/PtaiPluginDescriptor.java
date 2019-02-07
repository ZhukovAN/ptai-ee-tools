package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor;

import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiClient;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.rest.AgentAuthApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiPlugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastConfig;
import hudson.Extension;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.CopyOnWriteList;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.parboiled.common.StringUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Base64;
import java.util.List;

@Extension
public class PtaiPluginDescriptor extends BuildStepDescriptor<Builder> {

    private final CopyOnWriteList<PtaiSastConfig> sastConfigs = new CopyOnWriteList<PtaiSastConfig>();

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

    public ListBoxModel doFillUiProjectItems(@QueryParameter String sastConfigName) {
        ListBoxModel res = new ListBoxModel();
        PtaiSastConfig sastConfig = getSastConfig(sastConfigName);
        if (null == sastConfig) return res;
        if (StringUtils.isEmpty(sastConfig.getSastConfigPtaiHostUrl())) return res;
        if (StringUtils.isEmpty(sastConfig.getSastConfigPtaiCert())) return res;
        if (StringUtils.isEmpty(sastConfig.getSastConfigPtaiCertPwd())) return res;
        if (StringUtils.isEmpty(sastConfig.getSastConfigPtaiCaCerts())) return res;

        HostnameVerifier hostnameVerifier = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) { return true; }
        };

        ApiClient apiClient = new ApiClient();
        AgentAuthApi authApi = new AgentAuthApi(apiClient);
        authApi.getApiClient().setBasePath(sastConfig.getSastConfigPtaiHostUrl());

        ProjectsApi prjApi = new ProjectsApi();
        prjApi.getApiClient().setBasePath(sastConfig.getSastConfigPtaiHostUrl());

        byte[] decodedBytes = Base64.getDecoder().decode(sastConfig.getSastConfigPtaiCert().replaceAll("\n", ""));
        char[] certPwd = sastConfig.getSastConfigPtaiCertPwd().toCharArray();
        KeyStore appKeyStore = null;
        ApiResponse<String> authToken = null;
        try (InputStream certStream = new ByteArrayInputStream(decodedBytes)) {
            appKeyStore = KeyStore.getInstance("PKCS12");
            appKeyStore.load(certStream, certPwd);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(appKeyStore, certPwd);
            authApi.getApiClient().setKeyManagers(kmf.getKeyManagers());
            // Due to ApiClient specific keyManagers must be set before CA certificates
            authApi.getApiClient().setSslCaCert(new ByteArrayInputStream(sastConfig.getSastConfigPtaiCaCerts().getBytes()));
            authApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);

            prjApi.getApiClient().setKeyManagers(kmf.getKeyManagers());
            prjApi.getApiClient().setSslCaCert(new ByteArrayInputStream(sastConfig.getSastConfigPtaiCaCerts().getBytes()));
            prjApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);

            authToken = authApi.apiAgentAuthSigninGetWithHttpInfo("Agent");

            prjApi.getApiClient().setApiKeyPrefix("Bearer");
            prjApi.getApiClient().setApiKey(authToken.getData());

            com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiResponse<List<Project>> projects = prjApi.apiProjectsGetWithHttpInfo(true);
            for (Project prj : projects.getData())
                res.add(prj.getName(), prj.getId().toString());
        } catch (Exception e) {
            return res;
        }
        return res;
    }

    @Override
    public boolean configure(StaplerRequest theRq, JSONObject theFormData) throws FormException {
        theFormData = theFormData.getJSONObject("ptai");
        sastConfigs.replaceBy(theRq.bindJSONToList(PtaiSastConfig.class, theFormData.get("instanceConfig")));
        save();
        return true;
    }

    public String getDisplayName() {
        return "PT AI SAST";
    }
}
