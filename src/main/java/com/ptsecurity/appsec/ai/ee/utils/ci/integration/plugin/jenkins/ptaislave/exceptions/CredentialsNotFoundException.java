package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions;

import java.io.IOException;

public class CredentialsNotFoundException extends IOException {

    private static final long serialVersionUID = -2489306184948013529L;
    private String credentialsId;

    public CredentialsNotFoundException(String theCredentialsId) {
        this.credentialsId = theCredentialsId;
    }

    @Override
    public String getMessage() {
        return "No Jenkins Credentials found with ID '" + credentialsId + "'";
    }
}
