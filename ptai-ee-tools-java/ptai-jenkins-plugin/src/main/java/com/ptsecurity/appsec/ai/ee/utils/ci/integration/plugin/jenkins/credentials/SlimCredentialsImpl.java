package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.exceptions.CredentialsNotFoundException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.Util;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.CheckForNull;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class SlimCredentialsImpl extends BaseStandardCredentials implements SlimCredentials {
    @Getter
    String userName;
    @Getter
    Secret password;
    @Getter
    String serverCaCertificates;

    @DataBoundConstructor
    public SlimCredentialsImpl(CredentialsScope scope, String id, String description,
                               @CheckForNull String password, @CheckForNull String userName,
                               String serverCaCertificates) {
        super(scope, id, description);
        this.password = Util.fixEmptyAndTrim(password) == null ? null : Secret.fromString(password);
        this.userName = Util.fixEmptyAndTrim(userName);
        this.serverCaCertificates = Util.fixEmptyAndTrim(serverCaCertificates);
    }

    @Override
    public SlimCredentialsImpl clone() {
        try {
            return (SlimCredentialsImpl) super.clone();
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    public static SlimCredentialsImpl getCredentialsById(Item item, String credentialsId) throws CredentialsNotFoundException {
        if (item == null)
            // Construct a fake project
            item = new FreeStyleProject((ItemGroup) Jenkins.get(), "fake-" + UUID.randomUUID().toString());
        List<SlimCredentialsImpl> credentialsList = CredentialsProvider.lookupCredentials(
                SlimCredentialsImpl.class,
                item,
                item instanceof Queue.Task
                        ? Tasks.getAuthenticationOf((Queue.Task) item)
                        : ACL.SYSTEM,
                Collections.<DomainRequirement>emptyList());

        for (SlimCredentialsImpl credentials : credentialsList)
            if (credentials.getId().equals(credentialsId))
                return (SlimCredentialsImpl)credentials;
        throw new CredentialsNotFoundException(credentialsId);
    }

    @Extension
    public static class ServerCredentialsDescriptor extends BaseStandardCredentialsDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_credentials_slim_displayName();
        }

        public FormValidation doTestServerCaCertificates(
                @QueryParameter("serverCaCertificates") final String serverCaCertificates) {
            if (StringUtils.isEmpty(serverCaCertificates))
                return FormValidation.warning(Messages.validator_check_slim_serverCaCertificates_empty());
            try {
                List<X509Certificate> certs = new Client().checkCaCerts(serverCaCertificates);
                StringBuilder dn = new StringBuilder();
                for (X509Certificate cert : certs)
                    dn.append("{").append(cert.getSubjectDN().getName()).append("}, ");
                return FormValidation.ok(com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_test_serverCaCertificates_success("[" + StringUtils.removeEnd(dn.toString().trim(), ",") + "]"));
            } catch (Exception e) {
                return FormValidation.error(e, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_test_serverCaCertificates_failed());
            }
        }

        public FormValidation doCheckUserName(@QueryParameter("userName") String userName) {
            return Validator.doCheckFieldNotEmpty(userName, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_check_slim_userName_empty());
        }

        public FormValidation doCheckPassword(@QueryParameter("password") String password) {
            return Validator.doCheckFieldNotEmpty(password, com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages.validator_check_slim_password_empty());
        }
    }
}