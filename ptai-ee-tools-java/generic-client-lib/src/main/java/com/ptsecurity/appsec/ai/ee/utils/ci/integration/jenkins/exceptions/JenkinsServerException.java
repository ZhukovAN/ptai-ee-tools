package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import lombok.Getter;
import org.apache.http.HttpStatus;

public class JenkinsServerException extends JenkinsClientException {
    public JenkinsServerException(String message) {
        super(message, null);
    }

    public JenkinsServerException(String message, Exception inner) {
        super(message, inner);
        if (null == inner) return;
        if (inner instanceof ApiException)
            code = ((ApiException) inner).getCode();
    }

    @Getter
    protected int code = HttpStatus.SC_INTERNAL_SERVER_ERROR;
}
