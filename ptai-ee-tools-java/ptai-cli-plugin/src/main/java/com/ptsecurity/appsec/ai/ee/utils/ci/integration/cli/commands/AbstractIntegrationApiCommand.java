package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import lombok.NonNull;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;

@Log4j2
public class AbstractIntegrationApiCommand {
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
