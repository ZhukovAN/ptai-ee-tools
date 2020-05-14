package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.util.Secret;

import java.io.IOException;

public interface LegacyCredentials extends StandardCredentials {
    String getClientCertificate();
    Secret getClientKey();
    String getServerCaCertificates();
    LegacyCredentials clone();
}