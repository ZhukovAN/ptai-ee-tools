package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth;

import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils.PtaiJenkinsApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import hudson.Extension;
import hudson.util.FormValidation;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

@EqualsAndHashCode
public class TokenAuth extends Auth {
    @Getter
    private String userName;
    @DataBoundSetter
    public void setUserName(String theUserName) {
        this.userName = theUserName;
    }

    @Getter
    private String apiToken;
    @DataBoundSetter
    public void setApiToken(String theApiToken) {
        this.apiToken = theApiToken;
    }

    @DataBoundConstructor
    public TokenAuth() {}

    @Symbol("TokenAuth")
    @Extension
    public static class TokenAuthDescriptor extends AuthDescriptor {
        @Override
        public String getDisplayName() {
            return "Token Authentication";
        }

        public FormValidation doTestJenkinsConnection(
                @QueryParameter("sastConfigJenkinsHostUrl") final String sastConfigJenkinsHostUrl,
                @QueryParameter("sastConfigJenkinsJobName") final String sastConfigJenkinsJobName,
                @QueryParameter("sastConfigCaCerts") final String sastConfigCaCerts,
                @QueryParameter("userName") final String userName,
                @QueryParameter("apiToken") final String apiToken) throws IOException {
            try {
                if (StringUtils.isEmpty(sastConfigJenkinsHostUrl))
                    throw new PtaiException(Messages.validator_emptyJenkinsHostUrl());
                if (StringUtils.isEmpty(sastConfigJenkinsJobName))
                    throw new PtaiException(Messages.validator_emptyJenkinsJobName());
                if (StringUtils.isEmpty(sastConfigCaCerts))
                    if ("https".equalsIgnoreCase(new URL(sastConfigJenkinsHostUrl).getProtocol()))
                        throw new PtaiException(Messages.validator_emptyPtaiCaCerts());
                if (StringUtils.isEmpty(userName))
                    throw new PtaiException(Messages.validator_emptyJenkinsUserName());
                if (StringUtils.isEmpty(apiToken))
                    throw new PtaiException(Messages.validator_emptyJenkinsApiToken());

                SastJob jenkinsClient = new SastJob();
                jenkinsClient.setUrl(sastConfigJenkinsHostUrl);
                jenkinsClient.setCaCertsPem(sastConfigCaCerts);
                jenkinsClient.setJobName(sastConfigJenkinsJobName);
                jenkinsClient.setUserName(userName);
                jenkinsClient.setPassword(apiToken);
                jenkinsClient.init();
                return FormValidation.ok(Messages.validator_successSastJobName(jenkinsClient.testSastJob()));
            } catch (JenkinsClientException e) {
                return FormValidation.error(e, Messages.validator_failed());
            }
        }
    }
}
