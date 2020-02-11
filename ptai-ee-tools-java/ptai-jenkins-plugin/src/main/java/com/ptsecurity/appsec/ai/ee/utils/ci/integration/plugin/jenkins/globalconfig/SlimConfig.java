package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentStatus;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentialsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.SlimServerSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.Validator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import hudson.Extension;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import lombok.Getter;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.util.Collections;
import java.util.UUID;

public class SlimConfig extends BaseConfig {
    @Getter
    private SlimServerSettings slimServerSettings;

    @DataBoundConstructor
    public SlimConfig(
            final String configName,
            final SlimServerSettings slimServerSettings) {
        this.configName = configName;
        this.slimServerSettings = slimServerSettings;
    }

    public SlimConfigDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(SlimConfigDescriptor.class);
    }

    @Extension
    public static class SlimConfigDescriptor extends Descriptor<BaseConfig> {
        @Override public String getDisplayName() {
            return Messages.captions_config_slim_displayName();
        }
        public FormValidation doCheckConfigName(@QueryParameter("configName") String configName) {
            return Validator.doCheckFieldNotEmpty(configName, Messages.validator_check_field_empty());
        }
    }
}
