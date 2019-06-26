package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.ServerSettingsDescriptor;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.exceptions.CredentialsNotFoundException;
import hudson.model.Describable;
import hudson.model.Item;
import hudson.security.ACL;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

@EqualsAndHashCode
@ToString
public class ServerSettings implements Describable<ServerSettings>, Cloneable, Serializable {
    private static final Auth DEFAULT_AUTH = NoneAuth.INSTANCE;

    @Getter
    private String serverUrl;
    @Getter
    private String serverCredentialsId;
    @Getter
    private String jenkinsServerUrl;
    @Getter
    private String jenkinsJobName;
    @Getter
    private Auth jenkinsServerCredentials;

    @DataBoundConstructor
    public ServerSettings(
            final String serverUrl,
            final String serverCredentialsId,
            final String jenkinsServerUrl, final String jenkinsJobName,
            final Auth jenkinsServerCredentials) {
        this.serverUrl = fixApiUrl(serverUrl);
        this.serverCredentialsId = serverCredentialsId;
        this.jenkinsServerUrl = fixApiUrl(jenkinsServerUrl);
        this.jenkinsJobName = jenkinsJobName;
        this.jenkinsServerCredentials = (jenkinsServerCredentials != null) ? jenkinsServerCredentials : DEFAULT_AUTH;
    }

    public static String fixApiUrl(String apiUrl) {
        return StringUtils.removeEnd(apiUrl.trim(), "/");
    }

    public ServerSettingsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(ServerSettingsDescriptor.class);
    }
}
