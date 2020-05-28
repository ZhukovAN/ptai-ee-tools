package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;

public class ConflictException extends PtaiClientException {
    public ConflictException(String message) {
        super(message);
    }
}
