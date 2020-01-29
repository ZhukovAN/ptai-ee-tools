package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.JenkinsApiClientWrapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.client.JenkinsClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.client.PtaiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.*;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Call;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class SastService {
    @Autowired
    protected JenkinsClient jenkinsClient;

    @Autowired
    protected PtaiClient ptaiClient;

    public void upload(String project, MultipartFile file) {
        String token = ptaiClient.signIn();
        log.debug("PTAI token: {}", token);
        UUID projectId = PtaiProject.searchProject(ptaiClient.getPrjApi(), project)
                .orElseThrow(() -> new PtaiServerException("PT AI EE project search failed", null));

        Path path = null;
        try {
            path = Files.createTempFile("", ".ptai");
            Files.copy(file.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
            com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiResponse<Void> res = ptaiClient.getStoreApi().uploadSourcesWithHttpInfo(
                    projectId, path.toFile(),
                    null,null,null,null,null,null,
                    null,null,null,null,null);
            log.debug("Sources upload result: {}", res.getStatusCode());
            path.toFile().delete();
            if (200 != res.getStatusCode())
                throw new PtaiClientException("Sources upload failed");
        } catch (IOException | ApiException e) {
            if ((null != path) && path.toFile().exists()) path.toFile().delete();
            e.printStackTrace();
        }
    }

    public Optional<Integer> scanUiManaged(String project, String node) {
        return scanJsonManaged(project, node, null, null);
    }

    public Optional<Integer> scanJsonManaged(String project, String node, ScanSettings settings, Policy[] policy) {
        try {
            String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());
            JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(jenkinsClient, 5, 5000);

            RemoteAccessApi api = jenkinsClient.getJenkinsApi();

            FreeStyleProject prj = apiClient.callApi(() -> api.getJob(jobName));
            Integer buildNumber = prj.getNextBuildNumber();

            SastJob.JenkinsJsonParameter params = new SastJob.JenkinsJsonParameter();
            params.add("PTAI_PROJECT_NAME", Optional.ofNullable(project).orElse(""));
            params.add("PTAI_NODE_NAME", Optional.ofNullable(node).orElse(""));
            params.add("PTAI_SETTINGS_JSON", null == settings ? "" : new ObjectMapper().writeValueAsString(settings));
            params.add("PTAI_POLICY_JSON", null == policy ? "" : new ObjectMapper().writeValueAsString(policy));
            String paramsJson = new ObjectMapper().writeValueAsString(params);
            // Try to get crumb
            try {
                ApiResponse<DefaultCrumbIssuer> crumbData = apiClient.callApi(() -> api.getCrumbWithHttpInfo());
                final String crumb = crumbData.getData().getCrumb();
                log.debug("Crumb: {}", crumbData.getData().getCrumb());
                // Start SAST job
                apiClient.callApi(() -> api.postJobBuildWithHttpInfo(jobName, paramsJson, null, crumb));
            } catch (JenkinsServerException e) {
                log.debug("No CSRF token issued");
                apiClient.callApi(() -> api.postJobBuildWithHttpInfo(jobName, paramsJson, null, null));
            }
            return Optional.ofNullable(buildNumber);
        } catch (JsonProcessingException e) {
            log.error("Exception thrown while creating JSON parameters set", e);
            return Optional.empty();
        }
    }

    public Optional<JobState> getJobState(Integer buildNumber, Integer startPos) {
        JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(jenkinsClient, 5, 5000);
        RemoteAccessApi api = jenkinsClient.getJenkinsApi();

        String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());

        FreeStyleBuild build = null;
        boolean buildStarted = false;
        try {
            // Check: if build with defined number is started
            build = apiClient.callApi(() -> api.getJobBuild(jobName, buildNumber.toString()));
            if (null == build)
                throw new JenkinsServerException("Build is null but there weren't API exception raised");

            buildStarted = true;
            ApiResponse<String> sastJobLog = apiClient.callApi(() -> api.getJobProgressiveTextWithHttpInfo(jobName, buildNumber.toString(), startPos.toString()));
            if (HttpStatus.OK.value() != sastJobLog.getStatusCode())
                throw new JenkinsServerException("Failed to get job log");

            int pos = Integer.valueOf(Optional.ofNullable(sastJobLog)
                    .map(ApiResponse::getHeaders)
                    .map(map -> map.get("X-Text-Size"))
                    .map(list -> list.get(0)).orElse("0"));

            StringBuilder builder = new StringBuilder();
            if ((pos != startPos) && (null != sastJobLog.getData())) {
                String[] lines = sastJobLog.getData().split("\\r?\\n");
                for (String line : lines) {
                    builder.append(line);
                    builder.append("\r\n");
                }
            }

            String statusText = Optional.ofNullable(build.getResult()).orElse(JobState.StatusEnum.UNKNOWN.name());

            try {
                return Optional.of(new JobState()
                        .status(JobState.StatusEnum.valueOf(statusText))
                        .log(builder.toString())
                        .pos(pos));
            } catch (Exception e) {
                return Optional.of(new JobState()
                        .status(JobState.StatusEnum.UNKNOWN)
                        .log(builder.toString())
                        .pos(pos));
            }
        } catch (JenkinsServerException e) {
            if (!buildStarted && (HttpStatus.NOT_FOUND.value() == e.getCode()))
                // Trying to get build info for job that isn't started yet results in 404 status
                return Optional.of(new JobState()
                        .status(JobState.StatusEnum.UNKNOWN)
                        .log("Job isn't started yet")
                        .pos(0));
            else
                throw e;
        }
    }

    public Optional<List<String>> getJobResults(Integer buildNumber) {
        JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(jenkinsClient, 5, 5000);
        RemoteAccessApi api = jenkinsClient.getJenkinsApi();

        String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());

        FreeStyleBuild build = apiClient.callApi(() -> api.getJobBuild(jobName, buildNumber.toString()));
        if (null == build)
            throw new JenkinsServerException("Build is null but there weren't API exception raised");
        String statusText = Optional.ofNullable(build.getResult()).orElse(JobState.StatusEnum.UNKNOWN.name());

        List<String> res = new ArrayList<>();
        try {
            JobState.StatusEnum status = JobState.StatusEnum.valueOf(statusText);
            if ((JobState.StatusEnum.UNKNOWN == status) || (JobState.StatusEnum.ABORTED == status))
                throw new Exception();

            return Optional.of(build.getArtifacts().stream().map(Artifact::getRelativePath).collect(Collectors.toList()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public Optional<ReadableByteChannel> getJobResult(Integer buildNumber, String artifactRelPath) {
        JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(jenkinsClient, 5, 5000);
        RemoteAccessApi api = jenkinsClient.getJenkinsApi();

        String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());

        FreeStyleBuild build = apiClient.callApi(() -> api.getJobBuild(jobName, buildNumber.toString()));
        if (null == build)
            throw new JenkinsServerException("Build is null but there weren't API exception raised");
        String statusText = Optional.ofNullable(build.getResult()).orElse(JobState.StatusEnum.UNKNOWN.name());

        try {
            JobState.StatusEnum status = JobState.StatusEnum.valueOf(statusText);
            if ((JobState.StatusEnum.UNKNOWN == status) || (JobState.StatusEnum.ABORTED == status))
                throw new Exception();

            for (Artifact artifact : build.getArtifacts()) {
                if (!artifactRelPath.equals(artifact.getRelativePath())) continue;
                URL url = new URL(build.getUrl() + "artifact/" + artifactRelPath);
                Call call = api.getJobBuildArtifactCall(jobName, buildNumber.toString(), artifactRelPath, null);
                Response response = call.execute();

                ReadableByteChannel res = Channels.newChannel(response.body().byteStream());
                return Optional.of(res);
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Autowired
    private DiscoveryClient discoveryClient;

    public Optional<String> getPtaiGatewayUri() {
        return discoveryClient.getInstances(Constants.PTAI_GATEWAY_SERVICE_NAME)
                .stream()
                .map(si -> "https://" + si.getHost() + ":" + String.valueOf(si.getPort()))
                .findFirst();
    }
}
