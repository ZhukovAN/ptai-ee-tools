package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;

public class UserExistsException extends PtaiClientException {
    public UserExistsException(String message) {
        super(message);
    }
}
