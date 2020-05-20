package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.Callable;

@Log4j2
public abstract class BaseSlimAst {
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    public static class ExitCode {
        @Getter
        protected int code;

        public static final ExitCode SUCCESS = new ExitCode(0);
        public static final ExitCode FAILED = new ExitCode(1);
        public static final ExitCode WARNINGS = new ExitCode(2);
        public static final ExitCode ERROR = new ExitCode(3);
        public static final ExitCode INVALID_INPUT = new ExitCode(1000);
    }

    public void processApiException(@NonNull String action, @NonNull Exception e, boolean verbose) {
        String message = BaseClientException.getApiExceptionMessage(e);
        if (StringUtils.isNotEmpty(message))
            log.error("{} failed: {}", action, message);
        else
            log.error("{} failed", action);
        if (verbose) {
            String details = BaseClientException.getApiExceptionDetails(e);
            if (StringUtils.isNotEmpty(details))
                log.error("API returned: {}", details);
            log.trace("Stack trace:", e);
        }
    }
}
