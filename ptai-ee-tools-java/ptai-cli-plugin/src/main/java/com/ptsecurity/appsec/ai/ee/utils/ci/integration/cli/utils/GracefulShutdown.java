package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;

@Log4j2
@RequiredArgsConstructor
public class GracefulShutdown extends Thread {
    @Setter
    protected boolean stopped = false;

    protected final Base owner;
    protected final Client client;
    protected final Integer scanId;

    public void run() {
        if (stopped) return;
        if ((null != client) && (null != scanId)) {
            try {
                client.getSastApi().stopScan(scanId);
            } catch (ApiException e1) {
                owner.log("Build %d stop failed", scanId);
            }
        }
    }
}