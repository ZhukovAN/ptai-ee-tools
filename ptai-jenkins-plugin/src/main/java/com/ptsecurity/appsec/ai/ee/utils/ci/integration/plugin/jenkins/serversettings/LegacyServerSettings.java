package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.Auth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.NoneAuth;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.LegacyServerSettingsDescriptor;
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
@Symbol("LegacyServerSettings")
public class LegacyServerSettings implements Describable<LegacyServerSettings>, Cloneable, Serializable {
    private static final Auth DEFAULT_AUTH = NoneAuth.INSTANCE;

    //  Default maximum number on non-successful Jenkins API call retries
    public static final Integer DEFAULT_JENKINS_MAX_RETRY = 5;
    public static final Integer JENKINS_MAX_RETRY_FROM = 1;
    public static final Integer JENKINS_MAX_RETRY_TO = 50;

    public static final Integer DEFAULT_JENKINS_RETRY_DELAY = 5000;
    public static final Integer JENKINS_RETRY_DELAY_FROM = 500;
    public static final Integer JENKINS_RETRY_DELAY_TO = 60000;

    @Getter
    private String serverLegacyUrl;
    @Getter
    private String serverLegacyCredentialsId;
    @Getter
    private String jenkinsServerUrl;
    @Getter
    private String jenkinsJobName;
    @Getter
    private Auth jenkinsServerCredentials;
    @Getter
    private Integer jenkinsMaxRetry;
    @Getter
    private Integer jenkinsRetryDelay;

    @DataBoundConstructor
    public LegacyServerSettings(
            final String serverLegacyUrl,
            final String serverLegacyCredentialsId,
            final String jenkinsServerUrl, final String jenkinsJobName,
            final Auth jenkinsServerCredentials,
            final Integer jenkinsMaxRetry,
            final Integer jenkinsRetryDelay) {
        this.serverLegacyUrl = fixApiUrl(serverLegacyUrl);
        this.serverLegacyCredentialsId = serverLegacyCredentialsId;
        this.jenkinsServerUrl = fixApiUrl(jenkinsServerUrl);
        this.jenkinsJobName = jenkinsJobName;
        this.jenkinsServerCredentials = (jenkinsServerCredentials != null) ? jenkinsServerCredentials : DEFAULT_AUTH;
        this.jenkinsMaxRetry = jenkinsMaxRetry;
        this.jenkinsRetryDelay = jenkinsRetryDelay;
    }

    public static String fixApiUrl(String apiUrl) {
        return StringUtils.removeEnd(apiUrl.trim(), "/");
    }

    public LegacyServerSettingsDescriptor getDescriptor() {
        return Jenkins.get().getDescriptorByType(LegacyServerSettingsDescriptor.class);
    }
}
