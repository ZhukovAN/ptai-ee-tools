package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentialsImpl;
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
public class LegacyServerSettingsDescriptor extends Descriptor<LegacyServerSettings> {
    public LegacyServerSettingsDescriptor() {
        super(LegacyServerSettings.class);
    }
    @Override
    public String getDisplayName() {
        return "LegacyServerSettingsDescriptor";
    }

    @Getter
    ServerSettingsDefaults serverSettingsDefaults = new ServerSettingsDefaults();

    public static List<Auth.AuthDescriptor> getAuthDescriptors() {
        return Auth.getAll();
    }

    public static Auth.AuthDescriptor getDefaultAuthDescriptor() {
        return NoneAuth.DESCRIPTOR;
    }

    private static final Class<LegacyCredentials> BASE_CREDENTIAL_TYPE = LegacyCredentials.class;

    // Include any additional contextual parameters that you need in order to refine the
    // credentials list. For example, if the credentials will be used to connect to a remote server,
    // you might include the server URL form element as a @QueryParameter so that the domain
    // requirements can be built from that URL
    public ListBoxModel doFillServerLegacyCredentialsIdItems(
            @AncestorInPath Item item,
            @QueryParameter String serverLegacyCredentialsId) {
        if (item == null && !Jenkins.get().hasPermission(Jenkins.ADMINISTER) ||
                item != null && !item.hasPermission(Item.EXTENDED_READ))
            return new StandardListBoxModel().includeCurrentValue(serverLegacyCredentialsId);

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

    public FormValidation doCheckServerUrl(@QueryParameter("serverLegacyUrl") String serverLegacyUrl) {
        FormValidation res = Validator.doCheckFieldNotEmpty(serverLegacyUrl, Messages.validator_check_field_empty());
        if (FormValidation.Kind.OK != res.kind) return res;
        return Validator.doCheckFieldUrl(serverLegacyUrl, Messages.validator_check_url_incorrect());
    }

    public FormValidation doCheckJenkinsServerUrl(@QueryParameter("jenkinsServerUrl") String jenkinsServerUrl) {
        return this.doCheckServerUrl(jenkinsServerUrl);
    }

    public FormValidation doCheckJenkinsJobName(@QueryParameter("jenkinsJobName") String jenkinsJobName) {
        return Validator.doCheckFieldNotEmpty(jenkinsJobName, Messages.validator_check_field_empty());
    }

    public FormValidation doTestServer(
            @AncestorInPath Item item,
            @QueryParameter("serverLegacyUrl") final String serverLegacyUrl,
            @QueryParameter("serverLegacyCredentialsId") final String serverLegacyCredentialsId) {
        try {
            if (!Validator.doCheckFieldNotEmpty(serverLegacyUrl))
                throw new PtaiClientException(Messages.validator_check_serverUrl_empty());
            boolean urlInvalid = !Validator.doCheckFieldUrl(serverLegacyUrl);
            if (!Validator.doCheckFieldNotEmpty(serverLegacyCredentialsId))
                throw new PtaiClientException(Messages.validator_check_serverCredentialsId_empty());

            LegacyCredentials legacyCredentials = LegacyCredentialsImpl.getCredentialsById(item, serverLegacyCredentialsId);

            PtaiProject ptaiProject = new PtaiProject();
            ptaiProject.setVerbose(false);
            ptaiProject.setUrl(LegacyServerSettings.fixApiUrl(serverLegacyUrl));

            ptaiProject.setKeyPem(legacyCredentials.getClientCertificate());
            ptaiProject.setKeyPassword(legacyCredentials.getClientKey().getPlainText());
            ptaiProject.setCaCertsPem(legacyCredentials.getServerCaCertificates());
            String authToken = ptaiProject.init();
            return StringUtils.isEmpty(authToken)
                    ? FormValidation.error(Messages.validator_test_server_token_invalid())
                    : urlInvalid
                    ? FormValidation.warning(Messages.validator_test_server_success(authToken.substring(0, 10)))
                    : FormValidation.ok(Messages.validator_test_server_success(authToken.substring(0, 10)));
        } catch (Exception e) {
            return Validator.error(e);
        }
    }

    public FormValidation doCheckJenkinsMaxRetry(@QueryParameter final Integer jenkinsMaxRetry) {
        return Validator.doCheckFieldBetween(
                jenkinsMaxRetry, LegacyServerSettings.JENKINS_MAX_RETRY_FROM, LegacyServerSettings.JENKINS_MAX_RETRY_TO,
                Messages.validator_check_field_integer_range(LegacyServerSettings.JENKINS_MAX_RETRY_FROM, LegacyServerSettings.JENKINS_MAX_RETRY_TO));
    }

    public FormValidation doCheckJenkinsRetryDelay(@QueryParameter final Integer jenkinsRetryDelay) {
        return Validator.doCheckFieldBetween(
                jenkinsRetryDelay, LegacyServerSettings.JENKINS_RETRY_DELAY_FROM, LegacyServerSettings.JENKINS_RETRY_DELAY_TO,
                Messages.validator_check_field_integer_range(LegacyServerSettings.JENKINS_RETRY_DELAY_FROM, LegacyServerSettings.JENKINS_RETRY_DELAY_TO));
    }
}

