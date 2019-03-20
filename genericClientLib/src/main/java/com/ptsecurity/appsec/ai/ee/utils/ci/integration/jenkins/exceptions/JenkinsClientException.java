package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;

public class JenkinsClientException extends BaseClientException {
    public JenkinsClientException(String message, Throwable inner) {
        super(message, inner);
    }

    public JenkinsClientException(String message) {
        super(message, null);
    }
}
