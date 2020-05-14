package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.utils.TempFile;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.Client;
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
import liquibase.util.StringUtils;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Call;
import okhttp3.Response;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.*;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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

    protected Path tempFolder;

    public String upload(
            String project, MultipartFile file,
            int current, int total, String uploadId) {
        String res = uploadId;
        String token = ptaiClient.signIn();
        log.debug("PTAI token: {}", token);
        UUID projectId = PtaiProject.searchProject(ptaiClient.getPrjApi(), project).orElse(null);
        if (null == projectId) {
            projectId = PtaiProject.createProject(ptaiClient.getPrjApi(), project);
            log.info("Project {} not found. It will be now created for sources upload", project);
        }
        log.debug("PT AI project Id: {}", projectId.toString());

        Path path = null;
        try {
            // Is this a new upload?
            if (StringUtils.isEmpty(res)) {
                res = UUID.randomUUID().toString();
                log.debug("Generated upload Id: {}", res);
            }
            Path chunk = this.tempFolder.resolve(String.format("%s.%06d", res, current));
            Files.copy(file.getInputStream(), chunk, StandardCopyOption.REPLACE_EXISTING);
            log.debug("{} ({}) project's sources part {} of {} saved successfully to {}", project, projectId, current + 1, total, chunk.toAbsolutePath().toString());
            // Last chunk stored as a temp file - need to combine them and upload to PT AI EE server
            if (current == total - 1) {
                path = Files.createTempFile("", ".ptai");
                try (
                        OutputStream out = new FileOutputStream(path.toFile());) {
                    byte[] buffer = new byte[512 * 1024];
                    for (int i = 0 ; i < total ; i++) {
                        chunk = this.tempFolder.resolve(String.format("%s.%06d", res, i));
                        InputStream in = new FileInputStream(chunk.toFile());
                        do {
                            int bytesRead = in.read(buffer);
                            if (-1 == bytesRead) break;
                            out.write(buffer, 0, bytesRead);
                        } while (true);
                        in.close();
                        Files.deleteIfExists(chunk);
                    }
                    out.flush();
                }
                com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiResponse<Void> status = ptaiClient.getStoreApi().uploadSourcesWithHttpInfo(
                        projectId, path.toFile(),
                        null,null,null,null,null,null,
                        null,null,null,null,null);
                log.debug("Sources upload result: {}", status.getStatusCode());
                path.toFile().delete();
                if (200 != status.getStatusCode())
                    throw new PtaiClientException("Sources upload failed");
            }
        } catch (Exception e) {
            if ((null != path) && path.toFile().exists()) path.toFile().delete();
            e.printStackTrace();
        }
        return res;
    }

    public Optional<Integer> scanUiManaged(String project, String node) {
        return scanJsonManaged(project, node, null, null);
    }

    public Optional<Integer> scanJsonManaged(String project, String node, ScanSettings settings, Policy[] policy) {
        String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());
        JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(jenkinsClient, 5, 5000);

        RemoteAccessApi api = jenkinsClient.getJenkinsApi();

        FreeStyleProject prj = apiClient.callApi(() -> api.getJob(jobName));

        // Start SAST job
        ApiResponse<Void> buildQueueInfo = apiClient.callApi(() -> api.postJobBuildWithParametersWithHttpInfo(
                jobName, 0,
                Optional.ofNullable(node).orElse(""),
                Optional.ofNullable(project).orElse(""),
                null == settings ? "" : new ObjectMapper().writeValueAsString(settings),
                null == policy ? "" : new ObjectMapper().writeValueAsString(policy),
                apiClient.crumb()));
        // Looks like buildNumber means nothing when there's several jobs exist in queue. We need to use
        // queue ID that is assigned when build job is being put into the queue
        Integer queueId = Client.getQueueId(buildQueueInfo);
        return Optional.ofNullable(queueId);
    }

    public Optional<JobState> getJobState(Integer scanId, Integer startPos) {
        JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(jenkinsClient, 5, 5000);
        RemoteAccessApi api = jenkinsClient.getJenkinsApi();

        String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());

        FreeStyleBuild build = null;
        boolean buildStarted = false;
        try {
            // Check: if build with defined number is started
            Integer buildId = jenkinsClient.getBuildId(jobName, scanId);
            if (null == buildId)
                return Optional.of(new JobState()
                        .status(JobState.StatusEnum.UNKNOWN)
                        .log("Job isn't started yet")
                        .pos(0));
            build = apiClient.callApi(
                    () -> api.getJobBuild(jobName, buildId.toString()),
                    String.format("Get SAST job %d status", scanId));
            if (null == build)
                throw new JenkinsServerException("Build is null but there weren't API exception raised");

            buildStarted = true;
            ApiResponse<String> sastJobLog = apiClient.callApi(() -> api.getJobProgressiveTextWithHttpInfo(jobName, buildId.toString(), startPos.toString()));
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

    public Optional<List<String>> getJobResults(Integer scanId) {
        JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(jenkinsClient, 5, 5000);
        RemoteAccessApi api = jenkinsClient.getJenkinsApi();

        String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());

        Integer buildId = jenkinsClient.getBuildId(jobName, scanId);
        if (null == buildId)
            throw new JenkinsServerException(String.format("Build Id not found for scan Id %d", scanId));
        log.debug("Build Id {} found for scan Id {}", buildId, scanId);
        FreeStyleBuild build = apiClient.callApi(() -> api.getJobBuild(jobName, buildId.toString()));
        if (null == build)
            throw new JenkinsServerException("Build is null but there weren't API exception raised");
        String statusText = Optional.ofNullable(build.getResult()).orElse(JobState.StatusEnum.UNKNOWN.name());

        List<String> res = new ArrayList<>();
        try {
            JobState.StatusEnum status = JobState.StatusEnum.valueOf(statusText);
            if ((JobState.StatusEnum.UNKNOWN == status) || (JobState.StatusEnum.ABORTED == status))
                throw new Exception();
            res = build.getArtifacts().stream().map(Artifact::getRelativePath).collect(Collectors.toList());
            for (String artifact : res)
                log.debug("Build artifact: {}", artifact);
            return Optional.of(build.getArtifacts().stream().map(Artifact::getRelativePath).collect(Collectors.toList()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public Optional<ReadableByteChannel> getJobResult(Integer scanId, String artifactRelPath) {
        JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(jenkinsClient, 5, 5000);
        RemoteAccessApi api = jenkinsClient.getJenkinsApi();

        String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());

        Integer buildId = jenkinsClient.getBuildId(jobName, scanId);
        if (null == buildId)
            throw new JenkinsServerException(String.format("Build Id not found for scan Id %d", scanId));
        log.debug("Build Id {} found for scan Id {}", buildId, scanId);
        FreeStyleBuild build = apiClient.callApi(() -> api.getJobBuild(jobName, buildId.toString()));
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
                log.debug("Getting artifact from {}", url.toString());
                Call call = api.getJobBuildArtifactCall(jobName, buildId.toString(), artifactRelPath, null);
                Response response = call.execute();

                ReadableByteChannel res = Channels.newChannel(response.body().byteStream());
                return Optional.of(res);
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    protected com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiResponse<DefaultCrumbIssuer> crumb;

    public void stopScan(@NonNull Integer scanId) {
        log.info("SAST job termination request. Scan ID is {}", scanId);
        String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());
        jenkinsClient.stopJob(jobName, scanId);
    }

    @Autowired
    private DiscoveryClient discoveryClient;

    public Optional<String> getPtaiGatewayUri() {
        return discoveryClient.getInstances(Constants.PTAI_GATEWAY_SERVICE_NAME)
                .stream()
                .map(si -> "https://" + si.getHost() + ":" + String.valueOf(si.getPort()))
                .findFirst();
    }

    @PostConstruct
    public void init() throws IOException {
        this.tempFolder = Files.createTempDirectory("PTAI.");
    }

    @PreDestroy
    public void fini() throws IOException {
        FileUtils.deleteDirectory(this.tempFolder.toFile());
    }
}
