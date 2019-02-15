package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiClient;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.rest.AgentAuthApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.CredentialsAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.CredentialsNotFoundException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils.PtaiJenkinsApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.DefaultCrumbIssuer;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.kohsuke.stapler.QueryParameter;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

@Extension
public class PtaiSastConfigDescriptor extends Descriptor<PtaiSastConfig> {
    public PtaiSastConfigDescriptor() {
        super(PtaiSastConfig.class);
    }

    @Override
    public String getDisplayName() {
        return "PtaiSastConfigDescriptor"; //Messages.hostconfig_descriptor();
    }

    public FormValidation doCheckSastConfigUrlPtai(@QueryParameter("sastConfigPtaiHostUrl") String sastConfigPtaiHostUrl) {
        return doCheckUrl(sastConfigPtaiHostUrl);
    }

    public FormValidation doCheckSastConfigUrlJenkins(@QueryParameter("sastConfigJenkinsHostUrl") String sastConfigJenkinsHostUrl) {
        return doCheckUrl(sastConfigJenkinsHostUrl);
    }

    public FormValidation doCheckUrl(String url) {
        String[] schemes = {"http","https"};
        UrlValidator urlValidator = new UrlValidator(schemes);
        return (urlValidator.isValid(url)) ? FormValidation.ok() : FormValidation.error(Messages.validator_invalidUrl());
    }

    public FormValidation doTestPtaiConnection(
            @QueryParameter("sastConfigPtaiHostUrl") final String ptaiHostUrl,
            @QueryParameter("sastConfigPtaiCert") final String ptaiCert,
            @QueryParameter("sastConfigPtaiCertPwd") final String ptaiCertPwd,
            @QueryParameter("sastConfigCaCerts") final String ptaiCaCerts) throws IOException, ServletException {
        try {
            if (StringUtils.isEmpty(ptaiHostUrl))
                throw new PtaiException(Messages.validator_emptyPtaiHostUrl());
            if (StringUtils.isEmpty(ptaiCert))
                throw new PtaiException(Messages.validator_emptyPtaiCert());
            if (StringUtils.isEmpty(ptaiCaCerts))
                throw new PtaiException(Messages.validator_emptyPtaiCaCerts());
            HostnameVerifier hostnameVerifier = (hostname, session) -> true;

            ApiClient apiClient = new ApiClient();
            AgentAuthApi authApi = new AgentAuthApi(apiClient);
            apiClient.setBasePath(ptaiHostUrl);

            byte[] decodedBytes = Base64.getDecoder().decode(ptaiCert.replaceAll("\n", ""));
            char[] certPwd = ptaiCertPwd.toCharArray();
            KeyStore appKeyStore = null;
            ApiResponse<String> authToken = null;
            try (InputStream certStream = new ByteArrayInputStream(decodedBytes)) {
                appKeyStore = KeyStore.getInstance("PKCS12");
                appKeyStore.load(certStream, certPwd);
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(appKeyStore, certPwd);
                apiClient.setKeyManagers(kmf.getKeyManagers());
                apiClient.setSslCaCert(new ByteArrayInputStream(ptaiCaCerts.getBytes(StandardCharsets.UTF_8)));
                apiClient.getHttpClient().setHostnameVerifier(hostnameVerifier);
                authToken = authApi.apiAgentAuthSigninGetWithHttpInfo("Agent");
            }
            return FormValidation.ok(Messages.validator_successPtaiAuthToken(authToken.getData().substring(0, 10)));
        } catch (Exception e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    public FormValidation doTestPtaiCert(
            @QueryParameter("sastConfigPtaiCert") final String sastConfigPtaiCert,
            @QueryParameter("sastConfigPtaiCertPwd") final String sastConfigPtaiCertPwd) {
        byte[] decodedBytes = Base64.getDecoder().decode(sastConfigPtaiCert.replaceAll("\n", ""));
        try (InputStream is = new ByteArrayInputStream(decodedBytes)) {
            char[] tableauCertPassword = sastConfigPtaiCertPwd.toCharArray();
            // Import PKCS12 in KeyStore
            KeyStore appKeyStore = KeyStore.getInstance("PKCS12");
            appKeyStore.load(is, tableauCertPassword);
            X509Certificate l_objCert = (X509Certificate)appKeyStore.getCertificate(appKeyStore.aliases().nextElement());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(appKeyStore, tableauCertPassword);
            return FormValidation.ok(Messages.validator_successPtaiCertSubject(l_objCert.getSubjectDN().getName()));
        } catch (Exception e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    public FormValidation doTestPtaiCaCerts(
            @QueryParameter("sastConfigCaCerts") final String sastConfigCaCerts) {
        try {
            char[] password = null; // Any password will work.
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(new ByteArrayInputStream(sastConfigCaCerts.getBytes(StandardCharsets.UTF_8)));
            if (certificates.isEmpty())
                throw new IllegalArgumentException(Messages.validator_failedPtaiCaCerts());
            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(null, password);
            int index = 0;
            StringBuilder dn = new StringBuilder();
            for (Certificate certificate : certificates) {
                String certificateAlias = "ca" + index++;
                caKeyStore.setCertificateEntry(certificateAlias, certificate);
                dn.append("{").append(((X509Certificate) certificate).getSubjectDN().getName()).append("}, ");
            }
            dn = new StringBuilder("[" + StringUtils.removeEnd(dn.toString().trim(), ",") + "]");
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(caKeyStore);
            return FormValidation.ok(Messages.validator_successPtaiCaCertsSubjects(dn.toString()));
        } catch (Exception e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    public FormValidation doTestJenkinsConnection(
            @QueryParameter("sastConfigJenkinsHostUrl") final String sastConfigJenkinsHostUrl,
            @QueryParameter("sastConfigJenkinsJobName") final String sastConfigJenkinsJobName,
            @QueryParameter("sastConfigCaCerts") final String sastConfigCaCerts,
            @QueryParameter("sastConfigJenkinsAuth") final String sastConfigJenkinsAuth,
            @QueryParameter("credentials") final String credentials,
            @QueryParameter("userName") final String userName,
            @QueryParameter("apiToken") final String apiToken) throws IOException, ServletException {
        System.out.println(sastConfigJenkinsAuth);
        PtaiJenkinsApiClient apiClient = new PtaiJenkinsApiClient();
        RemoteAccessApi api = new RemoteAccessApi(apiClient);
        if (!StringUtils.isEmpty(credentials)) {
            // Retrieve credentials from Jenkins
            UsernamePasswordCredentials creds;
            try {
                creds = CredentialsAuth.getCredentials(null, credentials);
            } catch (CredentialsNotFoundException e) {
                return FormValidation.error(e, Messages.validator_failedGetCredentials());
            }
            apiClient.setUsername(creds.getUsername());
            apiClient.setPassword(creds.getPassword().getPlainText());
        } else if (!StringUtils.isEmpty(userName) && !StringUtils.isEmpty(apiToken)) {
            // Jenkins API tone authentication is not the same as JWT (i.e. "bearer" one)
            // It is just another form of login/password authentication
            apiClient.setUsername(userName);
            apiClient.setPassword(apiToken);
        }

        api.getApiClient().setBasePath(sastConfigJenkinsHostUrl);
        api.getApiClient().setSslCaCert(new ByteArrayInputStream(sastConfigCaCerts.getBytes(StandardCharsets.UTF_8)));
        api.getApiClient().getHttpClient().setHostnameVerifier((hostname, session) -> true);

        try {
            String l_strJobName = PtaiJenkinsApiClient.convertJobName(sastConfigJenkinsJobName);
            FreeStyleProject prj = api.getJob(l_strJobName);
            return FormValidation.ok(Messages.validator_successSastJobName(prj.getDisplayName()));
        } catch (ApiException e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    public static List<Auth.AuthDescriptor> getAuthDescriptors() {
        return Auth.getAll();
    }

    public static Auth.AuthDescriptor getDefaultAuthDescriptor() {
        return NoneAuth.DESCRIPTOR;
    }

}
