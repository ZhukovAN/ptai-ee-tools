package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.CertificateHelper;
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
import org.jetbrains.annotations.NotNull;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.CheckForNull;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class CredentialsImpl extends BaseStandardCredentials implements Credentials, Cloneable {
    @Getter
    Secret token;
    @Getter
    String serverCaCertificates;

    @DataBoundConstructor
    public CredentialsImpl(CredentialsScope scope, String id, String description,
                           @CheckForNull String token, String serverCaCertificates) {
        super(scope, id, description);
        this.token = Util.fixEmptyAndTrim(token) == null ? null : Secret.fromString(token);
        this.serverCaCertificates = Util.fixEmptyAndTrim(serverCaCertificates);
    }

    @Override
    public CredentialsImpl clone() {
        try {
            return (CredentialsImpl) super.clone();
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    public static CredentialsImpl getCredentialsById(Item item, String id) throws ApiException {
        if (item == null)
            // Construct a fake project
            item = new FreeStyleProject((ItemGroup) Jenkins.get(), "fake-" + UUID.randomUUID().toString());
        List<CredentialsImpl> credentials = CredentialsProvider.lookupCredentials(
                CredentialsImpl.class,
                item,
                item instanceof Queue.Task
                        ? Tasks.getAuthenticationOf((Queue.Task) item)
                        : ACL.SYSTEM,
                Collections.<DomainRequirement>emptyList());

        return credentials.stream()
                .filter(c -> c.getId().equals(id))
                .findAny()
                .orElseThrow(() -> ApiException.raise("Credentials retrieval failed", new IllegalArgumentException("No credentials found with ID " + id)));
    }

    @Extension
    public static class ServerCredentialsDescriptor extends BaseStandardCredentialsDescriptor {
        @NotNull
        @Override
        public String getDisplayName() {
            return Messages.captions_credentials_displayName();
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
                return FormValidation.ok(Messages.validator_check_serverCaCertificates_success("[" + StringUtils.removeEnd(dn.toString().trim(), ",") + "]"));
            } catch (ApiException e) {
                return Validator.error(e);
            } catch (Exception e) {
                return Validator.error(Messages.validator_check_serverCaCertificates_failed(), e);
            }
        }

        public FormValidation doCheckToken(@QueryParameter("token") String token) {
            return Validator.doCheckFieldNotEmpty(token, Messages.validator_check_token_empty());
        }
    }
}