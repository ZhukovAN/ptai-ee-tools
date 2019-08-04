package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import org.apache.commons.httpclient.HttpStatus;

import java.util.concurrent.Callable;

public class JenkinsApiClientWrapper {
    BaseClient baseClient;
    int jenkinsMaxRetry = 1;
    int jenkinsDelay = 5000;



    public JenkinsApiClientWrapper(BaseClient baseClient, int jenkinsMaxRetry, int jenkinsDelay) {
        this.baseClient = baseClient;
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
                    baseClient.log("Attempt %d failed. Cancel trying\r\n", attempt, jenkinsDelay);
                    throw e;
                } else {
                    baseClient.log("Attempt %d failed. Wait %d ms\r\n", attempt, jenkinsDelay);
                    baseClient.log(e);
                }
                attempt++;
            } catch (Exception e) {
                throw new JenkinsServerException("Unknown exception raised: ", e);
            }
        } while (true);
    }
}
