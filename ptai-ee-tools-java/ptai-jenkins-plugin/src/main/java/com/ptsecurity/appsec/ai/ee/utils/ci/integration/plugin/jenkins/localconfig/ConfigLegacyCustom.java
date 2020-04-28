package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.deprecated.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import hudson.Extension;
import lombok.Getter;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

public class ConfigLegacyCustom extends ConfigBase {
    @Getter
    private ServerSettings serverSettings;

    @Getter
    private LegacyServerSettings legacyServerSettings;

    @DataBoundConstructor
    public ConfigLegacyCustom(
            final ServerSettings serverSettings,
            final LegacyServerSettings legacyServerSettings) {
        this.serverSettings = serverSettings;
        this.legacyServerSettings = legacyServerSettings;
    }

    /*
     * see https://wiki.jenkins.io/display/JENKINS/Hint+on+retaining+backward+compatibility
     */
    @SuppressWarnings("deprecation")
    protected Object readResolve() {
        // Migrate ServerSettings to LegacyServerSettings
        if (null == legacyServerSettings && null != serverSettings)
            legacyServerSettings = new LegacyServerSettings(
                    serverSettings.getServerUrl(),
                    serverSettings.getServerCredentialsId(),
                    serverSettings.getJenkinsServerUrl(),
                    serverSettings.getJenkinsJobName(),
                    serverSettings.getJenkinsServerCredentials(),
                    serverSettings.getJenkinsMaxRetry(),
                    serverSettings.getJenkinsRetryDelay()
            );
        serverSettings = null;
        return this;
    }

    @Symbol("ConfigLegacyCustom")
    @Extension
    public static class Descriptor extends ConfigBaseDescriptor {
        @Override
        public String getDisplayName() {
            return Messages.captions_config_configLegacyCustom();
        }
    }
}
