package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import lombok.Getter;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;

public class JenkinsServerException extends JenkinsClientException {
    public JenkinsServerException(String message, Throwable inner) {
        super(message, inner);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (StringUtils.isNotEmpty(this.getMessage())) builder.append("Message: ").append(this.getMessage());
        if (null != this.inner) builder.append("\r\n").append("Inner: ").append(this.inner);
        return builder.toString();
    }
}
