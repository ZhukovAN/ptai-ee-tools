package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions;

import java.io.IOException;

public class PtaiException extends RuntimeException {
    public PtaiException(final String message) {
        super(message);
    }
}
