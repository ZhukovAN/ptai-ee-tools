package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;

public class EntityExistsException extends PtaiClientException {
    public EntityExistsException(String message) {
        super(message);
    }
}
