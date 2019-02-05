package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.CredentialsAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.CredentialsNotFoundException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils.PtaiJenkinsApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.server.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.server.StringUtil;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.server.rest.Version;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.server.rest.VersionControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.kohsuke.stapler.QueryParameter;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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

    public FormValidation doCheckSastConfigUrlPtai(@QueryParameter("sastConfigUrlPtai") String sastConfigUrlPtai) {
        return doCheckUrl(sastConfigUrlPtai);
    }

    public FormValidation doCheckSastConfigUrlJenkins(@QueryParameter("sastConfigUrlJenkins") String sastConfigUrlJenkins) {
        return doCheckUrl(sastConfigUrlJenkins);
    }

    public FormValidation doCheckUrl(String url) {
        String[] schemes = {"http","https"};
        UrlValidator urlValidator = new UrlValidator(schemes);
        return (urlValidator.isValid(url)) ? FormValidation.ok() : FormValidation.error(Messages.validator_invalidUrl());
    }

    public FormValidation doCheckPtaiServerPort(@QueryParameter("ptaiServerPort") int ptaiServerPort) {
        if ((ptaiServerPort > 0) && (ptaiServerPort < 65535))
            return FormValidation.ok();
        return FormValidation.error(Messages.validator_ptaiServerPort());
    }

    public FormValidation doTestPtaiConnection(
            @QueryParameter("sastConfigPtaiHostUrl") final String sastConfigPtaiHostUrl,
            @QueryParameter("sastConfigPtaiCert") final String sastConfigPtaiCert,
            @QueryParameter("sastConfigPtaiCertPwd") final String sastConfigPtaiCertPwd) throws IOException, ServletException {
        try {
            VersionControllerApi l_objApi = new VersionControllerApi();
            l_objApi.getApiClient().setBasePath(sastConfigPtaiHostUrl);
            Version l_objResponse = l_objApi.versionUsingGET();
            return FormValidation.ok("Success, PT AI EE integration server version is " + l_objResponse.getVersion());
        } catch (Exception e) {
            return FormValidation.error("Connection failed");
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
            return FormValidation.ok("Success, subject is " + l_objCert.getSubjectDN().getName());
        } catch (Exception e) {
            return FormValidation.error(e, "Verification failed");
        }
    }

    public FormValidation doTestPtaiCaCerts(
            @QueryParameter("sastConfigPtaiCaCerts") final String sastConfigPtaiCaCerts) {
        try {
            char[] password = null; // Any password will work.
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(new ByteArrayInputStream(sastConfigPtaiCaCerts.getBytes()));
            if (certificates.isEmpty())
                throw new IllegalArgumentException("Expected non-empty set of trusted certificates");
            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(null, password);
            int index = 0;
            String l_strDn = "";
            for (Certificate certificate : certificates) {
                String certificateAlias = "ca" + Integer.toString(index++);
                caKeyStore.setCertificateEntry(certificateAlias, certificate);
                l_strDn += ((X509Certificate)certificate).getSubjectDN().getName();
                l_strDn += ", ";
            }
            l_strDn = "[" + StringUtils.removeEnd(l_strDn, ",") + "]";
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(caKeyStore);
            return FormValidation.ok("Success, trusted certificates are " + l_strDn);
        } catch (Exception e) {
            return FormValidation.error(e, "Verification failed");
        }
    }

    public FormValidation doTestJenkinsConnection(
            @QueryParameter("sastConfigJenkinsHostUrl") final String sastConfigJenkinsHostUrl,
            @QueryParameter("sastConfigJenkinsJobName") final String sastConfigJenkinsJobName,
            @QueryParameter("sastConfigJenkinsAuth") final String sastConfigJenkinsAuth,
            @QueryParameter("credentials") final String credentials,
            @QueryParameter("userName") final String userName,
            @QueryParameter("apiToken") final String apiToken) throws IOException, ServletException {
        PtaiJenkinsApiClient apiClient = new PtaiJenkinsApiClient();
        RemoteAccessApi api = new RemoteAccessApi(apiClient);
        if (!StringUtils.isEmpty(credentials)) {
            UsernamePasswordCredentials creds;
            try {
                creds = CredentialsAuth.getCredentials(null, credentials);
            } catch (CredentialsNotFoundException e) {
                return FormValidation.error(e, "Failed to get credentials");
            }
            apiClient.setUsername(creds.getUsername());
            apiClient.setPassword(creds.getPassword().getPlainText());
        } else if (!StringUtils.isEmpty(userName) && !StringUtils.isEmpty(apiToken)) {
            apiClient.setApiKeyPrefix("Authorization");
            apiClient.setApiKey(Auth.generateAuthorizationHeaderValue("Basic", userName, apiToken));
        }

        api.getApiClient().setBasePath(sastConfigJenkinsHostUrl);
        String l_strJobName = apiClient.convertJobName(sastConfigJenkinsJobName);
        try {
            FreeStyleProject prj = api.getJob(l_strJobName);
            return FormValidation.ok("Success, job's display name is " + prj.getDisplayName());
        } catch (Exception e) {
            return FormValidation.error("Connection failed");
        }
    }

    public static List<Auth.AuthDescriptor> getAuthDescriptors() {
        return Auth.getAll();
    }

    public static Auth.AuthDescriptor getDefaultAuthDescriptor() {
        return NoneAuth.DESCRIPTOR;
    }

}
