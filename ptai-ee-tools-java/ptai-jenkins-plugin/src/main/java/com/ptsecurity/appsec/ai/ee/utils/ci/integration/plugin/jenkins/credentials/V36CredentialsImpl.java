package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.CertificateHelper;
import hudson.Extension;
import hudson.Util;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Queue;
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

public class V36CredentialsImpl extends BaseStandardCredentials implements V36Credentials {
    @Getter
    Secret password;
    @Getter
    String serverCaCertificates;

    @DataBoundConstructor
    public V36CredentialsImpl(CredentialsScope scope, String id, String description,
                              @CheckForNull String password, String serverCaCertificates) {
        super(scope, id, description);
        this.password = Util.fixEmptyAndTrim(password) == null ? null : Secret.fromString(password);
        this.serverCaCertificates = Util.fixEmptyAndTrim(serverCaCertificates);
    }

    @Override
    public V36CredentialsImpl clone() {
        try {
            return (V36CredentialsImpl) super.clone();
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    public static V36CredentialsImpl getCredentialsById(Item item, String id) throws ApiException {
        if (item == null)
            // Construct a fake project
            item = new FreeStyleProject((ItemGroup) Jenkins.get(), "fake-" + UUID.randomUUID().toString());
        List<V36CredentialsImpl> credentials = CredentialsProvider.lookupCredentials(
                V36CredentialsImpl.class,
                item,
                item instanceof Queue.Task
                        ? Tasks.getAuthenticationOf((Queue.Task) item)
                        : ACL.SYSTEM,
                Collections.<DomainRequirement>emptyList());

        return credentials.stream()
                .filter(c -> c.getId().equals(id))
                .findAny()
                .orElseThrow(() -> ApiException.raise("No credentials found with ID " + id, new IllegalArgumentException()));
    }

    @Extension
    public static class ServerCredentialsDescriptor extends BaseStandardCredentialsDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_credentials_v36_displayName();
        }

        public FormValidation doTestServerCaCertificates(
                @QueryParameter("serverCaCertificates") final String serverCaCertificates) {
            if (StringUtils.isEmpty(serverCaCertificates))
                return FormValidation.warning(Messages.validator_check_serverCaCertificates_empty());
            try {
                List<X509Certificate> certs = CertificateHelper.readPem(serverCaCertificates);
                StringBuilder dn = new StringBuilder();
                for (X509Certificate cert : certs)
                    dn.append("{").append(cert.getSubjectDN().getName()).append("}, ");
                return FormValidation.ok(Messages.validator_test_serverCaCertificates_success("[" + StringUtils.removeEnd(dn.toString().trim(), ",") + "]"));
            } catch (ApiException e) {
                return Validator.error(e);
            } catch (Exception e) {
                return Validator.error(Messages.validator_test_serverCaCertificates_failed(), e);
            }

    }
        public FormValidation doCheckPassword(@QueryParameter("password") String password) {
            return Validator.doCheckFieldNotEmpty(password, Messages.validator_check_v36_password_empty());
        }
    }
}