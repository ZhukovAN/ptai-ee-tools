package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.DefaultCrumbIssuer;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;

import java.util.concurrent.Callable;
import java.util.function.IntPredicate;

@Builder
@AllArgsConstructor
@Getter
@Setter
public class JenkinsApiClientWrapper {
    protected Client client;

    protected int jenkinsMaxRetry = 1;

    protected int jenkinsDelay = 5000;

    public <V> V callApi(Callable<V> call)
            throws JenkinsServerException {
        return this.callApi(call, null);
    }

    public void callApi(Runnable call) throws JenkinsServerException {
        this.callApi(call, null);
    }

    public void callApi(Runnable call, String stage) throws JenkinsServerException {
        Callable<Void> dummy = new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                call.run();
                return null;
            }
        };
        this.callApi(dummy, stage);
    }

    public <V> V callApi(Callable<V> call, IntPredicate treatCodeAsNull, String stage) throws JenkinsServerException {
        int attempt = 1;
        do {
            try {
                if (1 != attempt)
                    Thread.sleep(jenkinsDelay);
                return call.call();
            } catch (ApiException e) {
                if (treatCodeAsNull.test(e.getCode()))
                    return null;
                if (HttpStatus.SC_BAD_GATEWAY != e.getCode())
                    processException(e, stage);
                if (jenkinsMaxRetry <= attempt) {
                    client.log("Attempt %d failed. Cancel trying\r\n", attempt, jenkinsDelay);
                    processException(e, stage);
                } else {
                    client.log("Attempt %d failed. Wait %d ms\r\n", attempt, jenkinsDelay);
                    client.log(e);
                }
                attempt++;
            } catch (Exception e) {
                processException(e, stage);
            }
        } while (true);
    }

    public <V> V callApi(Callable<V> call, String stage) throws JenkinsServerException {
        return callApi(call, c -> (false), stage);
    }

    protected void processException(Exception e, String stage) throws JenkinsServerException {
        if (StringUtils.isNotEmpty(stage))
            throw new JenkinsServerException(String.format("Exception raised during stage: %s", stage), e);
        else
            throw new JenkinsServerException("Exception raised while calling embedded API", e);
    }

    public String crumb() {
        return new JenkinsApiClientWrapper(client, jenkinsMaxRetry, jenkinsDelay).callApi(this::getCrumb, "Get crumb");
    }

    protected String getCrumb() {
        try {
            ApiResponse<DefaultCrumbIssuer> response = client.getJenkinsApi().getCrumbWithHttpInfo();
            client.log("Crumb: %s\r\n", response.getData().getCrumb());
            return response.getData().getCrumb();
        } catch (ApiException dummy) {
            client.log("No CSRF token issued\r\n");
            return null;
        }
    }
}
