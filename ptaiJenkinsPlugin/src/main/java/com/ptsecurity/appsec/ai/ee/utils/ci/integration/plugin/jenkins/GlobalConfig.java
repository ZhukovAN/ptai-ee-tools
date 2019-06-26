package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.GlobalConfigDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.exceptions.CredentialsNotFoundException;
import hudson.model.Describable;
import hudson.model.Item;
import hudson.security.ACL;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

@EqualsAndHashCode
@ToString
public class GlobalConfig implements Describable<GlobalConfig>, Cloneable, Serializable {
    @Getter
    private String configName;

    @Getter
    private ServerSettings serverSettings;

    @DataBoundConstructor
    public GlobalConfig(
            final String configName,
            final ServerSettings serverSettings) {
        this.configName = configName;
        this.serverSettings = serverSettings;
    }

    public GlobalConfigDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(GlobalConfigDescriptor.class);
    }
}
