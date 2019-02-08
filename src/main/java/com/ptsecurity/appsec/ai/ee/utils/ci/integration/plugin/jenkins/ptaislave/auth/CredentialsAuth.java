package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.auth;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernameListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.CredentialsNotFoundException;
import hudson.Extension;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.Stapler;

import java.util.Collections;
import java.util.List;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;


public class CredentialsAuth extends Auth {
    @Getter
    private String credentials;
    @DataBoundSetter
    public void setCredentials(String theCredentials) {
        this.credentials = theCredentials;
    }

    @DataBoundConstructor
    public CredentialsAuth() {
        this.credentials = null;
    }

    public String getUserName(Item item) throws CredentialsNotFoundException {
        UsernamePasswordCredentials creds = getCredentials(item);
        return creds.getUsername();
    }

    public String getPassword(Item item) throws CredentialsNotFoundException {
        UsernamePasswordCredentials creds = getCredentials(item);
        return creds.getPassword().getPlainText();
    }

    /**
     * Looks up the credentialsID attached to this object in the Global Credentials plugin datastore
     * @param item the Item (Job, Pipeline,...) we are currently running in.
     *      The item is required to also get Credentials which are defined in the items scope and not Jenkins globally.
     *      Value can be null, but Credentials e.g. configured on a Folder will not be found in this case, only globally configured Credentials.
     * @return the matched credentials
     * @throws CredentialsNotFoundException if not found
     */
    private UsernamePasswordCredentials getCredentials(Item item) throws CredentialsNotFoundException {
        return getCredentials(item, this.credentials);
    }

    public static UsernamePasswordCredentials getCredentials(final Item item, final String credentials) throws CredentialsNotFoundException {
        List<StandardUsernameCredentials> listOfCredentials = CredentialsProvider.lookupCredentials(
                StandardUsernameCredentials.class, item, ACL.SYSTEM, Collections.<DomainRequirement> emptyList());

        for (StandardUsernameCredentials cred : listOfCredentials)
            if (credentials.equals(cred.getId()))
                return (UsernamePasswordCredentials)cred;
        throw new CredentialsNotFoundException(credentials);
    }

    @Symbol("CredentialsAuth")
    @Extension
    public static class CredentialsAuthDescriptor extends AuthDescriptor {
        @Override
        public String getDisplayName() {
            return "Credentials Authentication";
        }

        public static ListBoxModel doFillCredentialsItems() {
            StandardUsernameListBoxModel model = new StandardUsernameListBoxModel();

            Item item = Stapler.getCurrentRequest().findAncestorObject(Item.class);
            model.includeAs(ACL.SYSTEM, item, StandardUsernameCredentials.class);
            return model;
        }
    }
}
