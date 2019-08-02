package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import org.apache.commons.httpclient.HttpStatus;

import java.util.concurrent.Callable;

public class JenkinsApiClientWrapper {
    Base base;
    int jenkinsMaxRetry = 1;
    int jenkinsDelay = 5000;



    public JenkinsApiClientWrapper(Base base, int jenkinsMaxRetry, int jenkinsDelay) {
        this.base = base;
        this.jenkinsMaxRetry = jenkinsMaxRetry;
        this.jenkinsDelay = jenkinsDelay;
    }

    public <V> V callApi(Callable<V> call) throws ApiException, JenkinsServerException {
        int attempt = 1;
        do {
            try {
                if (1 != attempt)
                    Thread.sleep(jenkinsDelay);
                return call.call();
            } catch (ApiException e) {
                if (HttpStatus.SC_BAD_GATEWAY != e.getCode())
                    throw e;
                if (jenkinsMaxRetry <= attempt) {
                    base.log("Attempt %d failed. Cancel trying\r\n", attempt, jenkinsDelay);
                    throw e;
                } else {
                    base.log("Attempt %d failed. Wait %d ms\r\n", attempt, jenkinsDelay);
                    base.log(e);
                }
                attempt++;
            } catch (Exception e) {
                throw new JenkinsServerException("Unknown exception raised: ", e);
            }
        } while (true);
    }
}
