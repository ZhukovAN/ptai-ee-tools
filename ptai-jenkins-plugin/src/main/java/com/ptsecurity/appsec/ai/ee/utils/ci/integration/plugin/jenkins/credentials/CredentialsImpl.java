package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.misc.tools.helpers.CertificateHelper;
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
import lombok.NonNull;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.CheckForNull;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class CredentialsImpl extends BaseStandardCredentials implements Credentials, Cloneable {
    @Getter
    protected Secret token;
    @Getter
    protected String serverCaCertificates;

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

    public static CredentialsImpl getCredentialsById(Item item, String id) throws GenericException {
        if (item == null)
            // Construct a fake project
            item = new FreeStyleProject((ItemGroup) Jenkins.get(), "fake-" + UUID.randomUUID());
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
                .orElseThrow(() -> GenericException.raise("Credentials retrieval failed", new IllegalArgumentException("No credentials found with ID " + id)));
    }

    @Extension
    @Symbol("serverCredentials")
    public static class ServerCredentialsDescriptor extends BaseStandardCredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Resources.i18n_ast_settings_server_credentials_label();
        }

        @SuppressWarnings("unused") // Called by groovy view
        public FormValidation doTestServerCaCertificates(
                @QueryParameter("serverCaCertificates") final String serverCaCertificates) {
            if (StringUtils.isEmpty(serverCaCertificates))
                return FormValidation.warning(Resources.i18n_ast_settings_server_ca_pem_message_parse_empty());
            try {
                List<X509Certificate> certs = CertificateHelper.readPem(serverCaCertificates);
                StringBuilder dn = new StringBuilder();
                for (X509Certificate cert : certs)
                    dn.append("{").append(cert.getSubjectDN().getName()).append("}, ");
                return FormValidation.ok(Resources.i18n_ast_settings_server_ca_pem_message_parse_success("[" + StringUtils.removeEnd(dn.toString().trim(), ",") + "]"));
            } catch (GenericException e) {
                return Validator.error(e);
            } catch (Exception e) {
                return Validator.error(Resources.i18n_ast_settings_server_ca_pem_message_parse_failed_details(), e);
            }
        }

        @SuppressWarnings("unused") // Called by groovy view
        public FormValidation doCheckToken(@QueryParameter("token") String value) {
            return Validator.doCheckFieldNotEmpty(value, Resources.i18n_ast_settings_server_token_message_empty());
        }
    }
}