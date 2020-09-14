package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.V36Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.V36CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.V36ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import hudson.Extension;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;

import java.util.Collections;
import java.util.UUID;
import java.util.logging.Logger;

@Extension
public class V36ServerSettingsDescriptor extends Descriptor<V36ServerSettings> {
    public V36ServerSettingsDescriptor() {
        super(V36ServerSettings.class);
    }
    @Override
    public String getDisplayName() {
        return "V36ServerSettingsDescriptor";
    }

    public FormValidation doCheckServerUrl(@QueryParameter("serverUrl") String serverUrl) {
        FormValidation res = Validator.doCheckFieldNotEmpty(serverUrl, Messages.validator_check_field_empty());
        if (FormValidation.Kind.OK != res.kind) return res;
        return Validator.doCheckFieldUrl(serverUrl, Messages.validator_check_url_incorrect());
    }

    public FormValidation doTestServer(
            @AncestorInPath Item item,
            @QueryParameter("serverUrl") final String serverUrl,
            @QueryParameter("serverCredentialsId") final String serverCredentialsId) {
        try {
            if (!Validator.doCheckFieldNotEmpty(serverUrl))
                throw new RuntimeException(Messages.validator_check_serverUrl_empty());
            boolean urlInvalid = !Validator.doCheckFieldUrl(serverUrl);
            if (!Validator.doCheckFieldNotEmpty(serverCredentialsId))
                throw new RuntimeException(Messages.validator_check_serverCredentialsId_empty());

            V36Credentials credentials = V36CredentialsImpl.getCredentialsById(item, serverCredentialsId);

            Utils client = new Utils();
            client.setUrl(serverUrl);
            client.setToken(credentials.getPassword().getPlainText());
            if (!StringUtils.isEmpty(credentials.getServerCaCertificates()))
                client.setCaCertsPem(credentials.getServerCaCertificates());
            client.init();

            EnterpriseLicenseData licenseData = client.getLicenseData();
            String buildInfoText = Utils.getLicenseDataBanner(licenseData);
            // TODO: Add health check status data
            // ComponentsStatus statuses = client.getDiagnosticApi().getStatus();
            // String statusText = "PT AI: " + statuses.getPtai() + "; EMBEDDED: " + statuses.getEmbedded();
            String statusText = "License invalid";
            return !licenseData.getIsValid()
                    ? FormValidation.error(Messages.validator_test_server_fail(buildInfoText, statusText))
                    : urlInvalid
                    ? FormValidation.warning(Messages.validator_test_v36_server_success(buildInfoText))
                    : FormValidation.ok(Messages.validator_test_v36_server_success(buildInfoText));
        } catch (Exception e) {
            return Validator.error(e);
        }
    }

    private static final Class<V36Credentials> BASE_CREDENTIAL_TYPE = V36Credentials.class;

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
}

