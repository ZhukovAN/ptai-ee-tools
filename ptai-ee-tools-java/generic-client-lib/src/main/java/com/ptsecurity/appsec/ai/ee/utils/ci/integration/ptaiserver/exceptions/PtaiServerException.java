package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;

public class PtaiServerException extends PtaiClientException {
    public PtaiServerException(String message, Exception inner) {
        super(message, inner);
    }

    public PtaiServerException(String message) {
        super(message);
    }
}
