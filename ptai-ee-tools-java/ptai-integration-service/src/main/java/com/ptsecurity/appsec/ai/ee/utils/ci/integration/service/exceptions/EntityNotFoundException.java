package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;

public class EntityNotFoundException extends PtaiClientException {
    public EntityNotFoundException(String message) {
        super(message);
    }
}
