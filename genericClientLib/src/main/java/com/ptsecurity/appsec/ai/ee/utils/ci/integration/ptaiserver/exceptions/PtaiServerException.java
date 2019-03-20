package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;

public class PtaiServerException extends PtaiClientException {
    public PtaiServerException(String message, Throwable inner) {
        super(message, inner);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (StringUtils.isNotEmpty(this.getMessage())) builder.append("Message: ").append(this.getMessage());
        if (inner instanceof com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException) {
            com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException e = (com.ptsecurity.appsec.ai.ee.ptai.server.gateway.ApiException)inner;
            builder.append("\r\n")
                    .append("Details: ")
                    .append(String.format("code: %d, message: %s", e.getCode(), HttpStatus.getStatusText(e.getCode())));
        } else if (inner instanceof com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException) {
            com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException e = (com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException) inner;
            builder.append("\r\n")
                    .append("Details: ")
                    .append(String.format("code: %d, message: %s", e.getCode(), HttpStatus.getStatusText(e.getCode())));
        } else if (inner instanceof com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException) {
            com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException e = (com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException) inner;
            builder.append("\r\n")
                    .append("Details: ")
                    .append(String.format("code: %d, message: %s", e.getCode(), HttpStatus.getStatusText(e.getCode())));
        }

        if (null != this.inner) builder.append("\r\n").append("Inner: ").append(this.inner);
        return builder.toString();
    }

}
