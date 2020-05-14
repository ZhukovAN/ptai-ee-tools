package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions;

public class PtaiServerException extends PtaiClientException {
    public PtaiServerException(String message, Exception inner) {
        super(message, inner);
    }

    public PtaiServerException(String message) {
        super(message);
    }
}
