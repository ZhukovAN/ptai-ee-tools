package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.ServerSettingsDescriptor;
import hudson.model.Describable;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

@EqualsAndHashCode
@ToString
@Symbol("ServerSettings")
public class ServerSettings implements Describable<ServerSettings>, Serializable {
    @Getter
    private final String serverUrl;
    @Getter
    private final String serverCredentialsId;
    @Getter
    private final boolean serverInsecure;

    @DataBoundConstructor
    public ServerSettings(
            final String serverUrl,
            final String serverCredentialsId,
            final boolean serverInsecure) {
        this.serverUrl = fixApiUrl(serverUrl);
        this.serverCredentialsId = serverCredentialsId;
        this.serverInsecure = serverInsecure;
    }

    private static String fixApiUrl(String apiUrl) {
        return StringUtils.removeEnd(apiUrl.trim(), "/");
    }

    public ServerSettingsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(ServerSettingsDescriptor.class);
    }
}
