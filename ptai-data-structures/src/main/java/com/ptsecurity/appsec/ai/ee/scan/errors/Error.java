package com.ptsecurity.appsec.ai.ee.scan.errors;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@Builder
public class Error {
    private String type;
    private String message;

    private boolean critical;

    public enum Level {
        ERROR, WARN, INFO, DEBUG, TRACE
    }
    protected Level level;
}
