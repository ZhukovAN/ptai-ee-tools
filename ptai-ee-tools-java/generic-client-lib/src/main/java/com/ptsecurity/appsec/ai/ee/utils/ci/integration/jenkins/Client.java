package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.JenkinsApiClientWrapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleBuild;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

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

    public void stopJob(String jobName, FreeStyleBuild sastBuild) {
        JenkinsApiClientWrapper client = new JenkinsApiClientWrapper(this, 5, 5000);
        final String crumb = client.crumb();
        try {
            client.callApi(() -> { jenkinsApi.postCancelQueueItem(sastBuild.getQueueId(), crumb); return null; });
        } catch (JenkinsServerException e) {
            this.log("Queue item stop failed, SAST job may be started already");
            this.log(e);
            try {
                client.callApi(() -> { jenkinsApi.postJobBuildStop(jobName, sastBuild.getId(), crumb); return null; });
            } catch (JenkinsServerException e1) {
                this.log("Queue item stop failed, SAST job may be started already");
                this.log(e1);
            }
        }
    }
}
