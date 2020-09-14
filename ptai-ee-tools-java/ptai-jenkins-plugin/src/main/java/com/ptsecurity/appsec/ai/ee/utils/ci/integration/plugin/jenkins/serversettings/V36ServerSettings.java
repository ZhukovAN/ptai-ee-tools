package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.V36ServerSettingsDescriptor;
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
@Symbol("V36ServerSettings")
public class V36ServerSettings implements Describable<V36ServerSettings>, Cloneable, Serializable {
    @Getter
    private String serverUrl;
    @Getter
    private String serverCredentialsId;
    @DataBoundConstructor
    public V36ServerSettings(
            final String serverUrl,
            final String serverCredentialsId) {
        this.serverUrl = fixApiUrl(serverUrl);
        this.serverCredentialsId = serverCredentialsId;
    }

    public static String fixApiUrl(String apiUrl) {
        return StringUtils.removeEnd(apiUrl.trim(), "/");
    }

    public V36ServerSettingsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(V36ServerSettingsDescriptor.class);
    }
}
