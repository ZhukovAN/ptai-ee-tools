package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernameListBoxModel;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.exceptions.CredentialsNotFoundException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Queue;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@EqualsAndHashCode
public class CredentialsAuth extends Auth {
    @Getter
    private String credentialsId;

    @DataBoundConstructor
    public CredentialsAuth(final String credentialsId) {
        this.credentialsId = credentialsId;
    }

    public String getUserName(Item item) throws CredentialsNotFoundException {
        UsernamePasswordCredentials creds = getCredentialsById(item, credentialsId);
        return creds.getUsername();
    }

    public String getPassword(Item item) throws CredentialsNotFoundException {
        UsernamePasswordCredentials creds = getCredentialsById(item, credentialsId);
        return creds.getPassword().getPlainText();
    }

    /**
     * Looks up the credentialsID attached to this object in the Global Credentials plugin datastore
     * @param item the Item (Job, Pipeline,...) we are currently running in.
     *      The item is required to also get Credentials which are defined in the items scope and not Jenkins globally.
     *      Value can be null, but Credentials e.g. configured on a Folder will not be found in this case, only globally configured Credentials.
     * @return the matched credentialsId
     * @throws CredentialsNotFoundException if not found
     */
    private static UsernamePasswordCredentials getCredentialsById(Item item, String credentialsId) throws CredentialsNotFoundException {
        if (item == null)
            // Construct a fake project
            item = new FreeStyleProject((ItemGroup)Jenkins.get(), "fake-" + UUID.randomUUID().toString());
        List<StandardUsernameCredentials> credentialsList = CredentialsProvider.lookupCredentials(
                StandardUsernameCredentials.class,
                item,
                item instanceof Queue.Task
                        ? Tasks.getAuthenticationOf((Queue.Task) item)
                        : ACL.SYSTEM,
                Collections.<DomainRequirement>emptyList());

        for (StandardUsernameCredentials credentials : credentialsList)
            if (credentials.getId().equals(credentialsId))
                return (UsernamePasswordCredentials)credentials;
        throw new CredentialsNotFoundException(credentialsId);
    }

    @Symbol("CredentialsAuth")
    @Extension
    public static class CredentialsAuthDescriptor extends AuthDescriptor {
        @Override
        public String getDisplayName() {
            return "Credentials Authentication";
        }

        public static ListBoxModel doFillCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {
            if (item == null && !Jenkins.get().hasPermission(Jenkins.ADMINISTER) ||
                    item != null && !item.hasPermission(Item.EXTENDED_READ))
                return new StandardUsernameListBoxModel().includeCurrentValue(credentialsId);

            if (item == null)
                // Construct a fake project
                item = new FreeStyleProject((ItemGroup)Jenkins.get(), "fake-" + UUID.randomUUID().toString());
            return new StandardUsernameListBoxModel()
                    .includeMatchingAs(
                            item instanceof Queue.Task
                                    ? Tasks.getAuthenticationOf((Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardUsernameCredentials.class,
                            Collections.<DomainRequirement>emptyList(),
                            CredentialsMatchers.always());
        }

        public FormValidation doTestJenkinsServer(
                @AncestorInPath Item item,
                @QueryParameter("jenkinsServerUrl") final String jenkinsServerUrl,
                @QueryParameter("jenkinsJobName") final String jenkinsJobName,
                @QueryParameter("serverCredentialsId") final String serverCredentialsId,
                @QueryParameter("credentialsId") final String credentialsId) throws IOException {
            try {
                if (StringUtils.isEmpty(jenkinsServerUrl))
                    throw new JenkinsClientException(Messages.validator_emptyJenkinsHostUrl());
                if (StringUtils.isEmpty(jenkinsJobName))
                    throw new JenkinsClientException(Messages.validator_emptyJenkinsJobName());
                if (StringUtils.isEmpty(serverCredentialsId))
                    if ("https".equalsIgnoreCase(new URL(jenkinsServerUrl).getProtocol()))
                        throw new JenkinsClientException(Messages.validator_emptyPtaiCaCerts());
                if (StringUtils.isEmpty(credentialsId))
                    throw new JenkinsClientException(Messages.validator_emptyJenkinsCredentials());

                UsernamePasswordCredentials jenkinsCredentials = CredentialsAuth.getCredentialsById(item, credentialsId);
                ServerCredentials serverCredentials = ServerCredentialsImpl.getCredentialsById(item, serverCredentialsId);

                SastJob jenkinsClient = new SastJob();
                jenkinsClient.setUrl(jenkinsServerUrl);
                jenkinsClient.setCaCertsPem(serverCredentials.getServerCaCertificates());
                jenkinsClient.setJobName(jenkinsJobName);
                jenkinsClient.setUserName(jenkinsCredentials.getUsername());
                jenkinsClient.setPassword(jenkinsCredentials.getPassword().getPlainText());
                jenkinsClient.init();
                return FormValidation.ok(Messages.validator_successSastJobName(jenkinsClient.testSastJob()));
            } catch (Exception e) {
                return Validator.error(e);
            }
        }
    }
}
