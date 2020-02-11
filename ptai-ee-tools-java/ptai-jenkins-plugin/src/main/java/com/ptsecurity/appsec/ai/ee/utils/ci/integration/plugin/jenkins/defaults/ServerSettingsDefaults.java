package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.defaults;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;

public class ServerSettingsDefaults implements Describable<ServerSettingsDefaults> {
    public Integer getJenkinsMaxRetry() {
        return LegacyServerSettings.DEFAULT_JENKINS_MAX_RETRY;
    }

    public Integer getJenkinsRetryDelay() {
        return LegacyServerSettings.DEFAULT_JENKINS_RETRY_DELAY;
    }

    @Override
    public ServerSettingsDefaultsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(ServerSettingsDefaultsDescriptor.class);
    }

    @Extension
    public static final class ServerSettingsDefaultsDescriptor extends Descriptor<ServerSettingsDefaults> {
        @Override
        public String getDisplayName() {
            return "";
        }
    }
}
