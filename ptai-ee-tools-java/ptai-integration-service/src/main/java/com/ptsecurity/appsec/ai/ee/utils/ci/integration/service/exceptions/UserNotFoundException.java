package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;

public class UserNotFoundException extends PtaiClientException {
    public UserNotFoundException(String message) {
        super(message);
    }
}
