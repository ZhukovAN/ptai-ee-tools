package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.Item;
import hudson.util.FormValidation;
import lombok.EqualsAndHashCode;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.IOException;
import java.net.URL;

@EqualsAndHashCode(callSuper = false)
public class NoneAuth extends Auth {
    @Extension
    public static final AuthDescriptor DESCRIPTOR = new NoneAuthDescriptor();

    public static final NoneAuth INSTANCE = new NoneAuth();

    @DataBoundConstructor
    public NoneAuth() {}

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

        public FormValidation doTestJenkinsServer(
                @AncestorInPath Item item,
                @QueryParameter("jenkinsServerUrl") final String jenkinsServerUrl,
                @QueryParameter("jenkinsJobName") final String jenkinsJobName,
                @QueryParameter("serverLegacyCredentialsId") final String serverLegacyCredentialsId) throws IOException {
            try {
                boolean httpsRequired = "https".equalsIgnoreCase(new URL(jenkinsServerUrl).getProtocol());
                if (StringUtils.isEmpty(jenkinsServerUrl))
                    throw new JenkinsClientException(Messages.validator_emptyJenkinsHostUrl());
                if (StringUtils.isEmpty(jenkinsJobName))
                    throw new JenkinsClientException(Messages.validator_emptyJenkinsJobName());
                if (StringUtils.isEmpty(serverLegacyCredentialsId) && httpsRequired)
                    throw new JenkinsClientException(Messages.validator_emptyPtaiCaCerts());


                SastJob jenkinsClient = new SastJob();
                jenkinsClient.setUrl(jenkinsServerUrl);
                if (httpsRequired) {
                    LegacyCredentials legacyCredentials = LegacyCredentialsImpl.getCredentialsById(item, serverLegacyCredentialsId);
                    jenkinsClient.setCaCertsPem(legacyCredentials.getServerCaCertificates());
                }
                jenkinsClient.setJobName(jenkinsJobName);
                jenkinsClient.init();
                return FormValidation.ok(Messages.validator_successSastJobName(jenkinsClient.testSastJob()));
            } catch (Exception e) {
                return Validator.error(e);
            }
        }
    }
}