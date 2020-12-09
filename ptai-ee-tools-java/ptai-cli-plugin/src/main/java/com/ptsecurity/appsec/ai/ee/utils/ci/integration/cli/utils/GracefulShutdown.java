package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class GracefulShutdown extends Thread {
    @Setter
    protected boolean stopped = false;

    @NonNull
    protected final AstJob job;

    public void run() {
        if (stopped) return;
        try {
            job.stop();
        } catch (ApiException e) {
            job.severe(e);
        }
    }
}