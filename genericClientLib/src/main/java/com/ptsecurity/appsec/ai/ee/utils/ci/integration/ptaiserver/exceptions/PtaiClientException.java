package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;

public class PtaiClientException extends BaseClientException {
    public PtaiClientException(String message, Throwable inner) {
        super(message, inner);
    }
    public PtaiClientException(String message) {
        super(message, null);
    }
}
