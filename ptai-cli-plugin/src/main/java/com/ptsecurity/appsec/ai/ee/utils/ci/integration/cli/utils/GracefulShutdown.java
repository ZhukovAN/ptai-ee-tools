package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
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
    protected final GenericAstJob job;

    public void run() {
        if (stopped) return;
        try {
            job.stop();
        } catch (GenericException e) {
            job.severe(e);
        }
    }
}