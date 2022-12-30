package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v420.converters;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.server.v420.api.model.ErrorLevel;
import com.ptsecurity.appsec.ai.ee.server.v420.api.model.ScanErrorModel;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ScanErrorsConverter {
    private static final Map<ErrorLevel, Error.Level> ERROR_LEVEL_MAP = new HashMap<>();

    static {
        ERROR_LEVEL_MAP.put(ErrorLevel.ERROR, Error.Level.ERROR);
        ERROR_LEVEL_MAP.put(ErrorLevel.WARN, Error.Level.WARN);
        ERROR_LEVEL_MAP.put(ErrorLevel.INFO, Error.Level.INFO);
        ERROR_LEVEL_MAP.put(ErrorLevel.DEBUG, Error.Level.DEBUG);
        ERROR_LEVEL_MAP.put(ErrorLevel.TRACE, Error.Level.TRACE);
    }

    @NonNull
    public static Error convert(@NonNull final ScanErrorModel error) {
        return Error.builder()
                .type(error.getErrorType())
                .message(error.getMessage())
                .critical(Boolean.TRUE.equals(error.getIsCritical()))
                .level(ERROR_LEVEL_MAP.get(error.getLevel()))
                .build();
    }
}
