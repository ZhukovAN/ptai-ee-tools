package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.Credentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.CredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.QueryParameter;

import java.util.Collections;
import java.util.UUID;

@Extension
@Symbol("serverSettings")
@Slf4j
public class ServerSettingsDescriptor extends Descriptor<ServerSettings> {
    public ServerSettingsDescriptor() {
        super(ServerSettings.class);
    }

    public FormValidation doCheckServerUrl(@QueryParameter String value) {
        FormValidation res = Validator.doCheckFieldNotEmpty(value, Resources.i18n_ast_settings_server_url_message_empty());
        if (FormValidation.Kind.ERROR == res.kind) return res;
        return Validator.doCheckFieldUrl(value, Resources.i18n_ast_settings_server_url_message_invalid());
    }

    public static String lowerFirstLetter(@NonNull final String text) {
        if (StringUtils.isEmpty(text)) return "";
        if (1 == text.length()) return text.toLowerCase();
        return String.valueOf(text.charAt(0)).toLowerCase() + text.substring(1);
    }

    public FormValidation doTestServer(
            @AncestorInPath Item item,
            @QueryParameter("serverUrl") final String serverUrl,
            @QueryParameter("serverCredentialsId") final String serverCredentialsId,
            @QueryParameter("serverInsecure") final boolean serverInsecure) {
        try {
            log.trace("Test PT AI server {} connection", serverUrl);
            if (!Validator.doCheckFieldNotEmpty(serverUrl))
                throw new RuntimeException(Resources.i18n_ast_settings_server_url_message_empty());
            boolean urlInvalid = !Validator.doCheckFieldUrl(serverUrl);
            if (!Validator.doCheckFieldNotEmpty(serverCredentialsId))
                throw new RuntimeException(Resources.i18n_ast_settings_server_credentials_message_empty());

            Credentials credentials = CredentialsImpl.getCredentialsById(item, serverCredentialsId);

            PluginDescriptor pluginDescriptor = Jenkins.get().getDescriptorByType(PluginDescriptor.class);
            AdvancedSettings advancedSettings = new AdvancedSettings();
            advancedSettings.apply(pluginDescriptor.getAdvancedSettings());

            AbstractApiClient client = Factory.client(ConnectionSettings.builder()
                    .url(serverUrl)
                    .credentials(TokenCredentials.builder().token(credentials.getToken().getPlainText()).build())
                    .insecure(serverInsecure)
                    .caCertsPem(credentials.getServerCaCertificates())
                    .build(), advancedSettings);
            ServerCheckResult res = new Factory().checkServerTasks(client).check();
            return ServerCheckResult.State.ERROR.equals(res.getState())
                    ? FormValidation.error(res.text())
                    : ServerCheckResult.State.WARNING.equals(res.getState())
                    ? FormValidation.warning(res.text())
                    : FormValidation.ok(res.text());
        } catch (Exception e) {
            return Validator.error(e);
        }
    }

    private static final Class<Credentials> BASE_CREDENTIAL_TYPE = Credentials.class;

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
                .includeEmptyValue()
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

