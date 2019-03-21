package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.exceptions.PtaiException;
import hudson.Extension;
import hudson.util.FormValidation;
import lombok.EqualsAndHashCode;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.IOException;
import java.net.URL;

@EqualsAndHashCode(callSuper = false)
public class NoneAuth extends Auth {

    // private static final long serialVersionUID = -3128995428538415113L;

    @Extension
    public static final AuthDescriptor DESCRIPTOR = new NoneAuthDescriptor();

    public static final NoneAuth INSTANCE = new NoneAuth();

    @DataBoundConstructor
    public NoneAuth() {
    }

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

                SastJob jenkinsClient = new SastJob();
                jenkinsClient.setUrl(sastConfigJenkinsHostUrl);
                jenkinsClient.setCaCertsPem(sastConfigCaCerts);
                jenkinsClient.setJobName(sastConfigJenkinsJobName);
                jenkinsClient.init();
                return FormValidation.ok(Messages.validator_successSastJobName(jenkinsClient.testSastJob()));
            } catch (JenkinsClientException e) {
                return FormValidation.error(e, Messages.validator_failed());
            }
        }
    }
}