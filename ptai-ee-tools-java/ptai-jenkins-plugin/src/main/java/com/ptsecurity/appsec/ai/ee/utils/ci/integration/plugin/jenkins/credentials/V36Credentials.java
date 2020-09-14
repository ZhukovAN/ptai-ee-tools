package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.util.Secret;

public interface V36Credentials extends StandardCredentials {
    Secret getPassword();
    String getServerCaCertificates();
    V36Credentials clone();
}