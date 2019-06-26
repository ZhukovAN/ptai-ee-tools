package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.util.Secret;

import java.io.IOException;

public interface ServerCredentials extends StandardCredentials {
    String getClientCertificate();
    Secret getClientKey() throws IOException, InterruptedException;
    String getServerCaCertificates();
    ServerCredentials clone();
}