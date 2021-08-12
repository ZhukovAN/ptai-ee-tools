package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

@Getter
@Slf4j
@RequiredArgsConstructor
@SuperBuilder
public abstract class AbstractJob extends AbstractTool {
    public static final String DEFAULT_OUTPUT_FOLDER = ".ptai";
    public static final String DEFAULT_PTAI_URL = "https://ptai.domain.org:443";
    public static final boolean DEFAULT_INSECURE = true;
    public static final String DEFAULT_TOKEN = "";
    @NonNull
    @Builder.Default
    protected ConnectionSettings connectionSettings = ConnectionSettings.builder()
            .url(DEFAULT_PTAI_URL)
            .token(DEFAULT_TOKEN)
            .insecure(DEFAULT_INSECURE)
            .build();

    public enum JobExecutionResult {
        FAILED, INTERRUPTED, SUCCESS
    }

    @Getter
    @Builder.Default
    protected AbstractApiClient client = null;

    public JobExecutionResult execute() {
        try {
            init();
            validate();
            client = Factory.client(connectionSettings);
            client.setConsole(this);

            unsafeExecute();
            return JobExecutionResult.SUCCESS;
        } catch (GenericException e) {
            if (null != e.getCause() && e.getCause() instanceof InterruptedException) {
                // TODO: check if job was interrupted in the middle of scan process,
                //  i.e. we still may get some incomplete results from there
                log.debug("Job execution interrupted");
                return JobExecutionResult.INTERRUPTED;
            }
            severe(e.getDetailedMessage());
            log.error(e.getDetailedMessage(), e.getCause());
            return JobExecutionResult.FAILED;
        }
    }

    protected abstract void init() throws GenericException;

    protected void validate() throws GenericException {
        connectionSettings.validate();
    }

    protected abstract void unsafeExecute() throws GenericException;
}
