package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions;

import lombok.NoArgsConstructor;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;

@NoArgsConstructor
public class BaseClientException extends Exception {
    protected Throwable inner = null;

    protected String message = null;

    public Throwable getInfo() {
        if (null != this.inner)
            return this.inner;
        else
            return this;
    }

    @Override
    public String getMessage() {
        if (StringUtils.isNotEmpty(this.message))
            return this.message;
        if (null == this.inner)
            return "";
        if (StringUtils.isNotEmpty(this.inner.getMessage()))
            return this.inner.getMessage();
        if (inner instanceof com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException) {
            com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException e = (com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException)inner;
            return String.format("Code: %d, message: %s", e.getCode(), HttpStatus.getStatusText(e.getCode()));
        } else if (inner instanceof com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException) {
            com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException e = (com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException) inner;
            return String.format("Code: %d, message: %s", e.getCode(), HttpStatus.getStatusText(e.getCode()));
        } else if (inner instanceof com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException) {
            com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException e = (com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException) inner;
            return String.format("Code: %d, message: %s", e.getCode(), HttpStatus.getStatusText(e.getCode()));
        } else if (inner instanceof com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException) {
            com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException e = (com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException) inner;
            return String.format("Code: %d, message: %s", e.getCode(), HttpStatus.getStatusText(e.getCode()));
        }
        return "";
    }

    public BaseClientException(String message, Throwable inner) {
        super(message);
        this.inner = inner;
        this.message = message;
    }

    public BaseClientException(String message) {
        this(message, null);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (StringUtils.isNotEmpty(this.getMessage())) builder.append("Message: ").append(this.getMessage());
        if (null != this.inner) builder.append("\r\n").append("Inner: ").append(this.inner);
        return builder.toString();
    }
}
