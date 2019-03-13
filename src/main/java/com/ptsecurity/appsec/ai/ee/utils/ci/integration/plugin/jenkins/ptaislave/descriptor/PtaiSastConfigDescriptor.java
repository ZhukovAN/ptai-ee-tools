package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.descriptor;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiClient;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.gateway.rest.AgentAuthApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.PtaiSastConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.CredentialsAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.CredentialsNotFoundException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils.PtaiJenkinsApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.DefaultCrumbIssuer;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.verb.POST;

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

            PtaiProject ptaiProject = new PtaiProject();
            ptaiProject.setVerbose(false);
            ptaiProject.setUrl(ptaiHostUrl);
            ptaiProject.setKeyPem(ptaiCert);
            ptaiProject.setKeyPassword(ptaiCertPwd);
            ptaiProject.setCaCertsPem(ptaiCaCerts);
            String authToken = ptaiProject.init();
            return FormValidation.ok(Messages.validator_successPtaiAuthToken(authToken.substring(0, 10)));
        } catch (Exception e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    public FormValidation doTestPtaiCert(
            @QueryParameter("sastConfigPtaiCert") final String sastConfigPtaiCert,
            @QueryParameter("sastConfigPtaiCertPwd") final String sastConfigPtaiCertPwd) {
        try {
            KeyStore keyStore = new Client().checkKey(sastConfigPtaiCert, sastConfigPtaiCertPwd);
            X509Certificate l_objCert = (X509Certificate)keyStore.getCertificate(keyStore.aliases().nextElement());
            return FormValidation.ok(Messages.validator_successPtaiCertSubject(l_objCert.getSubjectDN().getName()));
        } catch (Exception e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    public FormValidation doTestPtaiCaCerts(
            @QueryParameter("sastConfigCaCerts") final String sastConfigCaCerts) {
        try {
            List<X509Certificate> certs = new Client().checkCaCerts(sastConfigCaCerts);
            StringBuilder dn = new StringBuilder();
            for (X509Certificate cert : certs)
                dn.append("{").append(cert.getSubjectDN().getName()).append("}, ");
            return FormValidation.ok(Messages.validator_successPtaiCaCertsSubjects("[" + StringUtils.removeEnd(dn.toString().trim(), ",") + "]"));
        } catch (Exception e) {
            return FormValidation.error(e, Messages.validator_failed());
        }
    }

    @POST
    public FormValidation doTestJenkinsConnection(final StaplerRequest request, final StaplerResponse response) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return FormValidation.ok();
    }

    public static List<Auth.AuthDescriptor> getAuthDescriptors() {
        return Auth.getAll();
    }

    public static Auth.AuthDescriptor getDefaultAuthDescriptor() {
        return NoneAuth.DESCRIPTOR;
    }

}
