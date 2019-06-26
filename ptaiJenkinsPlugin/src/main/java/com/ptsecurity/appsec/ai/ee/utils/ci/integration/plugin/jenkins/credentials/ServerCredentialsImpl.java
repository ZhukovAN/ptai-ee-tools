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
import org.kohsuke.stapler.verb.POST;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import javax.annotation.CheckForNull;

// TODO: Add enhanced certificate upload functions (see https://github.com/jenkinsci/credentials-plugin/blob/master/src/main/java/com/cloudbees/plugins/credentials/impl/CertificateCredentialsImpl.java)
public class ServerCredentialsImpl extends BaseStandardCredentials implements ServerCredentials {
    @Getter
    String clientCertificate;
    @Getter
    Secret clientKey;
    @Getter
    String serverCaCertificates;

    @DataBoundConstructor
    public ServerCredentialsImpl(CredentialsScope scope, String id, String description,
                                 @CheckForNull String clientKey, @CheckForNull String clientCertificate,
                                 @CheckForNull String serverCaCertificates) {
        super(scope, id, description);
        this.clientKey = Util.fixEmptyAndTrim(clientKey) == null ? null : Secret.fromString(clientKey);
        this.clientCertificate = Util.fixEmptyAndTrim(clientCertificate);
        this.serverCaCertificates = Util.fixEmptyAndTrim(serverCaCertificates);
    }

    @Override
    public ServerCredentials clone() {
        try {
            return (ServerCredentials) super.clone();
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    public static ServerCredentials getCredentialsById(Item item, String credentialsId) throws CredentialsNotFoundException {
        if (item == null)
            // Construct a fake project
            item = new FreeStyleProject((ItemGroup) Jenkins.get(), "fake-" + UUID.randomUUID().toString());
        List<ServerCredentials> credentialsList = CredentialsProvider.lookupCredentials(
                ServerCredentials.class,
                item,
                item instanceof Queue.Task
                        ? Tasks.getAuthenticationOf((Queue.Task) item)
                        : ACL.SYSTEM,
                Collections.<DomainRequirement>emptyList());

        for (ServerCredentials credentials : credentialsList)
            if (credentials.getId().equals(credentialsId))
                return (ServerCredentials)credentials;
        throw new CredentialsNotFoundException(credentialsId);
    }

    @Extension
    public static class ServerCredentialsDescriptor extends BaseStandardCredentialsDescriptor {
        @Override
        public String getDisplayName() {
            return "PTAI Server Certificate Authentication";
        }

        public FormValidation doTestServerCaCertificates(
                @QueryParameter("serverCaCertificates") final String serverCaCertificates) {
            try {
                List<X509Certificate> certs = new Client().checkCaCerts(serverCaCertificates);
                StringBuilder dn = new StringBuilder();
                for (X509Certificate cert : certs)
                    dn.append("{").append(cert.getSubjectDN().getName()).append("}, ");
                return FormValidation.ok(Messages.validator_test_serverCaCertificates_success("[" + StringUtils.removeEnd(dn.toString().trim(), ",") + "]"));
            } catch (Exception e) {
                return FormValidation.error(e, Messages.validator_test_serverCaCertificates_failed());
            }
        }

        public FormValidation doTestClientCertificate(
                @QueryParameter("clientCertificate") final String clientCertificate,
                @QueryParameter("clientKey") final String clientKey) {
            try {
                Secret decryptedClientKey = Secret.fromString(clientKey);
                KeyStore keyStore = new Client().checkKey(clientCertificate, decryptedClientKey.getPlainText());
                X509Certificate cert = (X509Certificate)keyStore.getCertificate(keyStore.aliases().nextElement());
                return FormValidation.ok(Messages.validator_test_clientCertificate_success(cert.getSubjectDN().getName()));
            } catch (Exception e) {
                return FormValidation.error(e, Messages.validator_test_clientCertificate_failed());
            }
        }

        public FormValidation doCheckClientCertificate(@QueryParameter("clientCertificate") String clientCertificate) {
            return Validator.doCheckFieldNotEmpty(clientCertificate, Messages.validator_check_clientCertificate_empty());
        }

        public FormValidation doCheckServerCaCertificates(@QueryParameter("serverCaCertificates") String serverCaCertificates) {
            return Validator.doCheckFieldNotEmpty(serverCaCertificates, Messages.validator_check_serverCaCertificates_empty());
        }
    }
}