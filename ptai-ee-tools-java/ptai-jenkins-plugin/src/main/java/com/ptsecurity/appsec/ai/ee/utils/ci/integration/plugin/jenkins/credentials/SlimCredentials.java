package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.util.Secret;

import java.io.IOException;

public interface SlimCredentials extends StandardCredentials {
    String getUserName();
    Secret getPassword() throws IOException, InterruptedException;
    String getServerCaCertificates();
    SlimCredentials clone();
}