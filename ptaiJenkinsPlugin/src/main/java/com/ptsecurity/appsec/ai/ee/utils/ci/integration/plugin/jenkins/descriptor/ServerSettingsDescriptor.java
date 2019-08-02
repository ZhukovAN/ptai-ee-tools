package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.defaults.ServerSettingsDefaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import hudson.Extension;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;
import org.parboiled.common.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Extension
public class ServerSettingsDescriptor extends Descriptor<ServerSettings> {
    public ServerSettingsDescriptor() {
        super(ServerSettings.class);
    }
    @Override
    public String getDisplayName() {
        return "ServerSettingsDescriptor";
    }

    @Getter
    ServerSettingsDefaults serverSettingsDefaults = new ServerSettingsDefaults();

    public static List<Auth.AuthDescriptor> getAuthDescriptors() {
        return Auth.getAll();
    }

    public static Auth.AuthDescriptor getDefaultAuthDescriptor() {
        return NoneAuth.DESCRIPTOR;
    }

    private static final Class<ServerCredentials> BASE_CREDENTIAL_TYPE = ServerCredentials.class;

    // Include any additional contextual parameters that you need in order to refine the
    // credentials list. For example, if the credentials will be used to connect to a remote server,
    // you might include the server URL form element as a @QueryParameter so that the domain
    // requirements can be built from that URL
    public ListBoxModel doFillServerCredentialsIdItems(
            @AncestorInPath Item item,
            @QueryParameter String serverCredentialsId) {
        if (item == null && !Jenkins.get().hasPermission(Jenkins.ADMINISTER) ||
                item != null && !item.hasPermission(Item.EXTENDED_READ))
            return new StandardListBoxModel().includeCurrentValue(serverCredentialsId);

        if (item == null)
            // Construct a fake project
            item = new FreeStyleProject((ItemGroup)Jenkins.get(), "fake-" + UUID.randomUUID().toString());
        return new StandardListBoxModel()
                .includeMatchingAs(
                        item instanceof Queue.Task
                                ? Tasks.getAuthenticationOf((Queue.Task) item)
                                : ACL.SYSTEM,
                        item,
                        BASE_CREDENTIAL_TYPE,
                        Collections.<DomainRequirement>emptyList(),
                        CredentialsMatchers.always());
    }

    public FormValidation doCheckServerUrl(@QueryParameter("serverUrl") String serverUrl) {
        FormValidation res = Validator.doCheckFieldNotEmpty(serverUrl, Messages.validator_check_field_empty());
        if (FormValidation.Kind.OK != res.kind) return res;
        return Validator.doCheckFieldUrl(serverUrl, Messages.validator_check_url_incorrect());
    }

    public FormValidation doCheckJenkinsServerUrl(@QueryParameter("jenkinsServerUrl") String jenkinsServerUrl) {
        return this.doCheckServerUrl(jenkinsServerUrl);
    }

    public FormValidation doCheckJenkinsJobName(@QueryParameter("jenkinsJobName") String jenkinsJobName) {
        return Validator.doCheckFieldNotEmpty(jenkinsJobName, Messages.validator_check_field_empty());
    }

    public FormValidation doTestServer(
            @AncestorInPath Item item,
            @QueryParameter("serverUrl") final String serverUrl,
            @QueryParameter("serverCredentialsId") final String serverCredentialsId) {
        try {
            if (!Validator.doCheckFieldNotEmpty(serverUrl))
                throw new PtaiClientException(Messages.validator_check_serverUrl_empty());
            if (!Validator.doCheckFieldUrl(serverUrl))
                throw new PtaiClientException(Messages.validator_check_serverUrl_incorrect());
            if (!Validator.doCheckFieldNotEmpty(serverCredentialsId))
                throw new PtaiClientException(Messages.validator_check_serverCredentialsId_empty());

            ServerCredentials serverCredentials = ServerCredentialsImpl.getCredentialsById(item, serverCredentialsId);

            PtaiProject ptaiProject = new PtaiProject();
            ptaiProject.setVerbose(false);
            ptaiProject.setUrl(ServerSettings.fixApiUrl(serverUrl));

            ptaiProject.setKeyPem(serverCredentials.getClientCertificate());
            ptaiProject.setKeyPassword(serverCredentials.getClientKey().getPlainText());
            ptaiProject.setCaCertsPem(serverCredentials.getServerCaCertificates());
            String authToken = ptaiProject.init();
            return StringUtils.isEmpty(authToken)
                    ? FormValidation.error(Messages.validator_test_server_token_invalid())
                    : FormValidation.ok(Messages.validator_test_server_success(authToken.substring(0, 10)));
        } catch (Exception e) {
            return Validator.error(e);
        }
    }

    public FormValidation doCheckJenkinsMaxRetry(@QueryParameter final Integer jenkinsMaxRetry) {
        return Validator.doCheckFieldBetween(
                jenkinsMaxRetry, ServerSettings.JENKINS_MAX_RETRY_FROM, ServerSettings.JENKINS_MAX_RETRY_TO,
                Messages.validator_check_field_integer_range(ServerSettings.JENKINS_MAX_RETRY_FROM, ServerSettings.JENKINS_MAX_RETRY_TO));
    }

    public FormValidation doCheckJenkinsRetryDelay(@QueryParameter final Integer jenkinsRetryDelay) {
        return Validator.doCheckFieldBetween(
                jenkinsRetryDelay, ServerSettings.JENKINS_RETRY_DELAY_FROM, ServerSettings.JENKINS_RETRY_DELAY_TO,
                Messages.validator_check_field_integer_range(ServerSettings.JENKINS_RETRY_DELAY_FROM, ServerSettings.JENKINS_RETRY_DELAY_TO));
    }
}

