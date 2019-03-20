package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions;

import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;

@NoArgsConstructor
public class BaseClientException extends Exception {
    protected Throwable inner = null;

    public Throwable getInfo() {
        if (null == this.inner)
            return this.inner;
        else
            return this;
    }

    public BaseClientException(String message, Throwable inner) {
        super(message);
        this.inner = inner;
    }

    public BaseClientException(String message) {
        this(message, null);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (StringUtils.isNotEmpty(this.getMessage())) builder.append("Message: ").append(this.getMessage());
        if (null != this.inner) builder.append("\r\n").append("Inner: ").append(this.inner);
        return builder.toString();
    }
}
