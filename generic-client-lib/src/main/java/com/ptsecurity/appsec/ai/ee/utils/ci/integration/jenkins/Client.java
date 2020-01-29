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
import org.apache.commons.lang3.StringUtils;

@Getter @Setter
public class Client extends BaseClient {
    protected final RemoteAccessApi jenkinsApi = new RemoteAccessApi(new ApiClient());

    protected String userName = null;

    protected String password = null;

    protected String token = null;

    private Integer jenkinsMaxRetry;

    private Integer jenkinsRetryDelay;

    public Client init() throws JenkinsClientException, JenkinsServerException {
        try {
            super.baseInit();
            super.initClients(jenkinsApi);
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
}
