package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.deprecated.ServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

@EqualsAndHashCode
@ToString
public class LegacyConfig extends BaseConfig {
    @Getter
    private ServerSettings serverSettings;

    @Getter
    private LegacyServerSettings legacyServerSettings;

    @DataBoundConstructor
    public LegacyConfig(
            final String configName,
            final ServerSettings serverSettings,
            final LegacyServerSettings legacyServerSettings) {
        this.configName = configName;
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

    public LegacyConfigDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(LegacyConfigDescriptor.class);
    }

    @Extension
    public static class LegacyConfigDescriptor extends Descriptor<BaseConfig> {
        public FormValidation doCheckConfigName(@QueryParameter("configName") String configName) {
            return Validator.doCheckFieldNotEmpty(configName, Messages.validator_check_field_empty());
        }

        @Override public String getDisplayName() {
            return Messages.captions_config_legacy_displayName();
        }
    }
}
