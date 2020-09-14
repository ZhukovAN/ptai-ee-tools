package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.JenkinsApiClientWrapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    public void stopJob(String jobName, Integer scanId) {
        JenkinsApiClientWrapper client = new JenkinsApiClientWrapper(this, jenkinsMaxRetry, jenkinsRetryDelay);
        final String crumb = client.crumb();

        Integer buildId = getBuildId(jobName, scanId);
        try {
            if (null == buildId)
                // Build still in the queue, let's remove it from there
                client.callApi(() -> {
                    jenkinsApi.postCancelQueueItem(scanId, crumb);
                    return null;
                });
            else
                client.callApi(() -> {
                    jenkinsApi.postJobBuildStop(jobName, buildId.toString(), crumb);
                    return null;
                });
        } catch (JenkinsServerException e) {
            //  Jenkins API cancelItem redirects to missing URL, so we need to ignore 404 error
            if (HttpStatus.SC_NOT_FOUND == e.getCode()) return;
            out("Queue item stop failed, SAST job may be started already");
            verbose("AST job stop failed", e);
        }
    }

    public static Integer getQueueId(ApiResponse<Void> response) {
        final String queueIdRegex = "^.+/queue/item/([0-9]+)/$";
        Integer res = null;
        do {
            Map<String, List<String>> headers = response.getHeaders();
            if (null == headers) break;
            List<String> locations = headers.getOrDefault("Location", new ArrayList<>(0));
            String location = locations.stream().filter(l -> l.matches(queueIdRegex)).findAny().orElse(null);
            if (null == location) break;
            Matcher matcher = Pattern.compile(queueIdRegex).matcher(location);
            matcher.matches();
            res = Integer.valueOf(matcher.group(1));
        } while (false);
        return res;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Build {
        @JsonProperty("number")
        protected int number;
        @JsonProperty("queueId")
        protected int queueId;
    }

    public Integer getBuildId(String jobName, Integer queueId) throws JenkinsServerException {
        Integer res = null;
        final String xpath = String.format("//build[queueId=%d]", queueId);
        JenkinsApiClientWrapper client = new JenkinsApiClientWrapper(this, jenkinsMaxRetry, jenkinsRetryDelay);
        try {
            String xml = client.callApi(
                    () -> jenkinsApi.getJobBuildExt(jobName, "builds[number,queueId]", xpath),
                    c -> (c == HttpStatus.SC_NOT_FOUND),
                    String.format("Getting extended job info for queueId %d", queueId));
            return (null == xml) ? null : new XmlMapper().readValue(xml, Build.class).number;
        } catch (JenkinsServerException e) {
            out("Queued ID %d build not found, assuming it wasn't started yet", queueId);
            verbose("Build ID read failed", e);
            throw e;
        } catch (IOException e) {
            throw new JenkinsServerException("Failed to parse server response", e);
        }
    }
}
