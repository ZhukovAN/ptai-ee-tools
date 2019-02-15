package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.CredentialsNotFoundException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils.PtaiJenkinsApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import hudson.Extension;
import hudson.util.FormValidation;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class NoneAuth extends Auth {

    // private static final long serialVersionUID = -3128995428538415113L;

    @Extension
    public static final AuthDescriptor DESCRIPTOR = new NoneAuthDescriptor();

    public static final NoneAuth INSTANCE = new NoneAuth();


    @DataBoundConstructor
    public NoneAuth() {
    }
    /*
    @Override
    public void setAuthorizationHeader(URLConnection connection, BuildContext context) throws IOException {
        //TODO: Should remove potential existing header, but URLConnection does not provide means to do so.
        //      Setting null worked in the past, but is not valid with newer versions (of Jetty).
        //connection.setRequestProperty("Authorization", null);
    }
    */
    /*
    @Override
    public String toString() {
        return "'" + getDescriptor().getDisplayName() + "'";
    }

    @Override
    public String toString(Item item) {
        return toString();
    }
    */
    @Override
    public AuthDescriptor getDescriptor() {
        return DESCRIPTOR;
    }

    @Symbol("NoneAuth")
    public static class NoneAuthDescriptor extends AuthDescriptor {
        @Override
        public String getDisplayName() {
            return "No Authentication";
        }

        public FormValidation doTestJenkinsConnection(
                @QueryParameter("sastConfigJenkinsHostUrl") final String sastConfigJenkinsHostUrl,
                @QueryParameter("sastConfigJenkinsJobName") final String sastConfigJenkinsJobName,
                @QueryParameter("sastConfigCaCerts") final String sastConfigCaCerts) throws IOException {
            try {
                if (StringUtils.isEmpty(sastConfigJenkinsHostUrl))
                    throw new PtaiException(Messages.validator_emptyJenkinsHostUrl());
                if (StringUtils.isEmpty(sastConfigJenkinsJobName))
                    throw new PtaiException(Messages.validator_emptyJenkinsJobName());
                if (StringUtils.isEmpty(sastConfigCaCerts))
                    if ("https".equalsIgnoreCase(new URL(sastConfigJenkinsHostUrl).getProtocol()))
                        throw new PtaiException(Messages.validator_emptyPtaiCaCerts());
                PtaiJenkinsApiClient apiClient = new PtaiJenkinsApiClient();
                RemoteAccessApi api = new RemoteAccessApi(apiClient);
                api.getApiClient().setBasePath(sastConfigJenkinsHostUrl);
                if ("https".equalsIgnoreCase(new URL(sastConfigJenkinsHostUrl).getProtocol())) {
                    api.getApiClient().setSslCaCert(new ByteArrayInputStream(sastConfigCaCerts.getBytes(StandardCharsets.UTF_8)));
                    api.getApiClient().getHttpClient().setHostnameVerifier((hostname, session) -> true);
                }
                String l_strJobName = PtaiJenkinsApiClient.convertJobName(sastConfigJenkinsJobName);
                FreeStyleProject prj = api.getJob(l_strJobName);
                return FormValidation.ok(Messages.validator_successSastJobName(prj.getDisplayName()));
            } catch (ApiException e) {
                return FormValidation.error(e, Messages.validator_failed());
            }
        }
    }
    /*
    @Override
    public int hashCode() {
        return "NoneAuth".hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return this.getClass().isInstance(obj);
    }
    */
}