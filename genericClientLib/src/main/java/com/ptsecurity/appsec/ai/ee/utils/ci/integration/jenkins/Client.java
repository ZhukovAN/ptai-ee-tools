package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;

public class Client extends BaseClient {
    @Getter
    protected final RemoteAccessApi jenkinsApi = new RemoteAccessApi(new ApiClient());
    @Getter
    @Setter
    protected String userName = null;
    @Getter
    @Setter
    protected String password = null;
    @Getter
    @Setter
    protected String token = null;
    @Getter
    @Setter
    private Integer jenkinsMaxRetry;
    @Getter
    @Setter
    private Integer jenkinsRetryDelay;

    public Client init() throws JenkinsClientException, JenkinsServerException {
        try {
            super.baseInit();
            super.initClients(jenkinsApi.getApiClient());
            if (StringUtils.isNotEmpty(this.userName)) {
                jenkinsApi.getApiClient().setUsername(this.userName);
                if (StringUtils.isNotEmpty(this.password))
                    jenkinsApi.getApiClient().setPassword(this.password);
                else if (StringUtils.isNotEmpty(this.token))
                    jenkinsApi.getApiClient().setPassword(this.token);
                else
                    throw new JenkinsClientException("Password or token must be set");
            }
            return this;
        } catch (BaseClientException e) {
            throw new JenkinsClientException(e.getMessage(), e);
        }
    }

    public void log(ApiException e) {
        this.log("ApiException thrown with code %d (%s)\r\n", e.getCode(), HttpStatus.getStatusText(e.getCode()));
        super.log(e);
    }
}
