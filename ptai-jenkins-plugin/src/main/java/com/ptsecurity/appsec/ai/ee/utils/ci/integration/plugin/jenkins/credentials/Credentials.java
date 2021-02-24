package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.util.Secret;

public interface Credentials extends StandardCredentials {
    Secret getToken();
    String getServerCaCertificates();
    Credentials clone();
}