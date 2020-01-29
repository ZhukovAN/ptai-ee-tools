package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import lombok.AllArgsConstructor;
import org.apache.http.HttpStatus;

import java.util.concurrent.Callable;

@AllArgsConstructor
public class JenkinsApiClientWrapper {
    protected BaseClient baseClient;

    protected int jenkinsMaxRetry = 1;

    protected int jenkinsDelay = 5000;

    public <V> V callApi(Callable<V> call) throws JenkinsServerException {
        int attempt = 1;
        do {
            try {
                if (1 != attempt)
                    Thread.sleep(jenkinsDelay);
                return call.call();
            } catch (ApiException e) {
                if (HttpStatus.SC_BAD_GATEWAY != e.getCode())
                    throw new JenkinsServerException("Exception raised while calling embedded Jenkins API", e);
                if (jenkinsMaxRetry <= attempt) {
                    baseClient.log("Attempt %d failed. Cancel trying\r\n", attempt, jenkinsDelay);
                    throw new JenkinsServerException("Exception raised while calling embedded Jenkins API", e);
                } else {
                    baseClient.log("Attempt %d failed. Wait %d ms\r\n", attempt, jenkinsDelay);
                    baseClient.log(e);
                }
                attempt++;
            } catch (Exception e) {
                throw new JenkinsServerException("Exception raised while calling embedded Jenkins API", e);
            }
        } while (true);
    }
}
