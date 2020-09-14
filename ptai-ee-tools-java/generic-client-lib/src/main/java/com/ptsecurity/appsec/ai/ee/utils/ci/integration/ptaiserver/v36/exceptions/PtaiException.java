package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.exceptions;

import lombok.NonNull;

public class PtaiException extends RuntimeException {
    public PtaiException(@NonNull final String message) {
        super(message);
    }
}
