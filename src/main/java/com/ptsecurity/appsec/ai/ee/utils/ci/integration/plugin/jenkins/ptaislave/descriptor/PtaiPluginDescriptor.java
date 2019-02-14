package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor;

import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiClient;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.rest.AgentAuthApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiPlugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import hudson.AbortException;
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

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSession;
import javax.servlet.ServletException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Extension @Symbol("ptaiUiSast")
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

    public ListBoxModel doFillUiProjectItems(@QueryParameter String sastConfigName) {
        ListBoxModel res = new ListBoxModel();
        PtaiSastConfig sastConfig = getSastConfig(sastConfigName);
        if (null == sastConfig) return res;
        if (StringUtils.isEmpty(sastConfig.getSastConfigPtaiHostUrl())) return res;
        if (StringUtils.isEmpty(sastConfig.getSastConfigPtaiCert())) return res;
        if (StringUtils.isEmpty(sastConfig.getSastConfigPtaiCertPwd())) return res;
        if (StringUtils.isEmpty(sastConfig.getSastConfigCaCerts())) return res;

        HostnameVerifier hostnameVerifier = (hostname, session) -> true;

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
            authApi.getApiClient().setSslCaCert(new ByteArrayInputStream(sastConfig.getSastConfigCaCerts().getBytes(StandardCharsets.UTF_8)));
            authApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);

            prjApi.getApiClient().setKeyManagers(kmf.getKeyManagers());
            prjApi.getApiClient().setSslCaCert(new ByteArrayInputStream(sastConfig.getSastConfigCaCerts().getBytes(StandardCharsets.UTF_8)));
            prjApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);

            authToken = authApi.apiAgentAuthSigninGetWithHttpInfo("Agent");

            prjApi.getApiClient().setApiKeyPrefix("Bearer");
            prjApi.getApiClient().setApiKey(authToken.getData());

            com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiResponse<List<Project>> projects = prjApi.apiProjectsGetWithHttpInfo(true);
            for (Project prj : projects.getData())
                res.add(prj.getName(), prj.getId().toString());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException | ApiException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException e) {
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

            // Connect to PT AI server
            HostnameVerifier hostnameVerifier = (hostname, session) -> true;

            AgentAuthApi authApi = new AgentAuthApi(new com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiClient());
            ProjectsApi prjApi = new ProjectsApi(new com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiClient());

            authApi.getApiClient().setBasePath(cfg.getSastConfigPtaiHostUrl());
            prjApi.getApiClient().setBasePath(cfg.getSastConfigPtaiHostUrl());

            byte[] decodedBytes = Base64.getDecoder().decode(cfg.getSastConfigPtaiCert().replaceAll("\n", ""));
            char[] certPwd = cfg.getSastConfigPtaiCertPwd().toCharArray();
            KeyStore appKeyStore;
            ApiResponse<String> authToken;
            try (InputStream certStream = new ByteArrayInputStream(decodedBytes)) {
                // Set certificates and keys for mutual PT AI EE server authentication
                appKeyStore = KeyStore.getInstance("PKCS12");
                appKeyStore.load(certStream, certPwd);
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(appKeyStore, certPwd);
                authApi.getApiClient().setKeyManagers(kmf.getKeyManagers());
                prjApi.getApiClient().setKeyManagers(kmf.getKeyManagers());
                // Due to ApiClient specific keyManagers must be set before CA certificates
                authApi.getApiClient().setSslCaCert(new ByteArrayInputStream(cfg.getSastConfigCaCerts().getBytes(StandardCharsets.UTF_8)));
                prjApi.getApiClient().setSslCaCert(new ByteArrayInputStream(cfg.getSastConfigCaCerts().getBytes(StandardCharsets.UTF_8)));
                authApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);
                prjApi.getApiClient().getHttpClient().setHostnameVerifier(hostnameVerifier);
                // Try to authenticate
                authToken = authApi.apiAgentAuthSigninGetWithHttpInfo("Agent");
                if (StringUtils.isEmpty(authToken.getData()))
                    throw new AbortException(Messages.validator_failedPtaiServerAuth());

                // Search for project
                prjApi.getApiClient().setApiKeyPrefix("Bearer");
                prjApi.getApiClient().setApiKey(authToken.getData());
                com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiResponse<List<Project>> projects;
                projects = prjApi.apiProjectsGetWithHttpInfo(true);
                UUID projectId = null;
                String uiPrj = Util.fixEmptyAndTrim(uiProject);

                for (Project prj : projects.getData())
                    if (uiPrj.equals(prj.getName())) {
                        projectId = prj.getId();
                        break;
                    }
                if (null == projectId)
                    throw new PtaiException(Messages.validator_failedPtaiProjectByName());
                return FormValidation.ok(Messages.validator_successPtaiProjectByName(projectId.toString().substring(0, 4)));
            } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException e) {
                throw new PtaiException(Messages.validator_failedPtaiCertificate(), e);
            } catch (ApiException | com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException e) {
                throw new PtaiException(Messages.validator_failedPtaiApi(), e);
            }
        } catch (PtaiException e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    public String getDisplayName() {
        return Messages.pluginStepName();
    }

    public FormValidation doCheckSastConfigName(@QueryParameter("sastConfigName") String sastConfigName) {
        return doCheckField(sastConfigName, Messages.validator_emptyConfigName());
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
