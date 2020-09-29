package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.java.Log;

import java.util.UUID;

@Log
@RequiredArgsConstructor
public class GracefulShutdown extends Thread {
    @Setter
    protected boolean stopped = false;

    @NonNull
    protected final Base owner;
    @NonNull
    protected final Project project;
    @NonNull
    protected final UUID scanResultId;

    public void run() {
        if (stopped) return;
        try {
            project.stop(scanResultId);
        } catch (ApiException e) {
            owner.severe("Build stop failed", e);
        }
    }
}