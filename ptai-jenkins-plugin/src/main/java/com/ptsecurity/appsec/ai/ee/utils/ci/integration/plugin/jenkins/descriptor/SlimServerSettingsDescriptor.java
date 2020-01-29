package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentStatus;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.LegacyCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.defaults.ServerSettingsDefaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.SlimServerSettings;
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
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Extension
public class SlimServerSettingsDescriptor extends Descriptor<SlimServerSettings> {
    public SlimServerSettingsDescriptor() {
        super(SlimServerSettings.class);
    }
    @Override
    public String getDisplayName() {
        return "SlimServerSettingsDescriptor";
    }

    public FormValidation doCheckServerUrl(@QueryParameter("serverSlimUrl") String serverSlimUrl) {
        FormValidation res = Validator.doCheckFieldNotEmpty(serverSlimUrl, Messages.validator_check_field_empty());
        if (FormValidation.Kind.OK != res.kind) return res;
        return Validator.doCheckFieldUrl(serverSlimUrl, Messages.validator_check_url_incorrect());
    }

    public FormValidation doTestServer(
            @AncestorInPath Item item,
            @QueryParameter("serverSlimUrl") final String serverSlimUrl,
            @QueryParameter("serverSlimCredentialsId") final String serverSlimCredentialsId) {
        try {
            if (!Validator.doCheckFieldNotEmpty(serverSlimUrl))
                throw new PtaiClientException(Messages.validator_check_serverUrl_empty());
            if (!Validator.doCheckFieldUrl(serverSlimUrl))
                throw new PtaiClientException(Messages.validator_check_serverUrl_incorrect());
            if (!Validator.doCheckFieldNotEmpty(serverSlimCredentialsId))
                throw new PtaiClientException(Messages.validator_check_serverCredentialsId_empty());

            SlimCredentials slimCredentials = SlimCredentialsImpl.getCredentialsById(item, serverSlimCredentialsId);

            Client client = new Client();
            client.setUrl(serverSlimUrl);
            client.setClientId(Plugin.CLIENT_ID);
            client.setClientSecret(Plugin.CLIENT_SECRET);
            client.setUserName(slimCredentials.getUserName());
            client.setPassword(slimCredentials.getPassword().getPlainText());
            if (!StringUtils.isEmpty(slimCredentials.getServerCaCertificates()))
                client.setCaCertsPem(slimCredentials.getServerCaCertificates());
            client.init();
            BuildInfo buildInfo = client.getPublicApi().getBuildInfoUsingGET();
            String buildInfoText = buildInfo.getName() + ".v" + buildInfo.getVersion() + " from " + buildInfo.getDate();

            ComponentsStatus statuses = client.getDiagnosticApi().getComponentsStatusUsingGET();
            String statusText = "PTAI: " + statuses.getPtai() + "; EMBEDDED: " + statuses.getEmbedded();
            return  (statuses.getPtai().equals(ComponentStatus.SUCCESS) && statuses.getEmbedded().equals(ComponentStatus.SUCCESS))
                    ? FormValidation.ok(Messages.validator_test_slim_server_success(buildInfoText))
                    : FormValidation.error(Messages.validator_test_slim_server_fail(buildInfoText, statusText));
        } catch (Exception e) {
            return Validator.error(new BaseClientException("Test failed", e));
        }
    }

    private static final Class<SlimCredentials> BASE_CREDENTIAL_TYPE = SlimCredentials.class;

    // Include any additional contextual parameters that you need in order to refine the
    // credentials list. For example, if the credentials will be used to connect to a remote server,
    // you might include the server URL form element as a @QueryParameter so that the domain
    // requirements can be built from that URL
    public ListBoxModel doFillServerSlimCredentialsIdItems(
            @AncestorInPath Item item,
            @QueryParameter String serverSlimCredentialsId) {
        if (item == null && !Jenkins.get().hasPermission(Jenkins.ADMINISTER) ||
                item != null && !item.hasPermission(Item.EXTENDED_READ))
            return new StandardListBoxModel().includeCurrentValue(serverSlimCredentialsId);

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

