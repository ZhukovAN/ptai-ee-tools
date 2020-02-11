package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.SlimServerSettingsDescriptor;
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
@Symbol("SlimServerSettings")
public class SlimServerSettings implements Describable<SlimServerSettings>, Cloneable, Serializable {
    @Getter
    private String serverSlimUrl;
    @Getter
    private String serverSlimCredentialsId;
    @DataBoundConstructor
    public SlimServerSettings(
            final String serverSlimUrl,
            final String serverSlimCredentialsId) {
        this.serverSlimUrl = fixApiUrl(serverSlimUrl);
        this.serverSlimCredentialsId = serverSlimCredentialsId;
    }

    public static String fixApiUrl(String apiUrl) {
        return StringUtils.removeEnd(apiUrl.trim(), "/");
    }

    public SlimServerSettingsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(SlimServerSettingsDescriptor.class);
    }
}
