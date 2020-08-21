package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentStatus;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.Node;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils.JenkinsApiClientWrapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.client.JenkinsClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.client.PtaiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.config.ConsulConfig;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.ComputerSet;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.FreeStyleProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.HudsonMasterComputer;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest.RemoteAccessApi;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.consul.ConsulProperties;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
public class DiagnosticService {
    @Autowired
    private DiscoveryClient discoveryClient;

    @Autowired
    protected JenkinsClient jenkinsClient;

    @Autowired
    protected PtaiClient ptaiClient;

    public UUID getProjectByName(String projectName) {
        String token = ptaiClient.signIn();
        return PtaiProject.searchProject(ptaiClient.getPrjApi(), projectName).orElse(null);
    }

    public ComponentsStatus getComponentsStatus() {
        ComponentsStatus res = new ComponentsStatus().embedded(ComponentStatus.SUCCESS).ptai(ComponentStatus.SUCCESS);
        try {
            List<String> serviceNames = discoveryClient.getServices();
            List<ServiceInstance> services = discoveryClient.getInstances(Constants.PTAI_GATEWAY_SERVICE_NAME);
            String url = discoveryClient.getInstances(Constants.PTAI_GATEWAY_SERVICE_NAME)
                    .stream()
                    .map(si -> "https://" + si.getHost() + ":" + String.valueOf(si.getPort()))
                    .findFirst().orElseThrow(() -> new PtaiClientException("PT AI EE gateway info not found in Consul"));
            log.debug("PT AI EE gateway URL is {}", url);
            String token = ptaiClient.signIn();
            if (StringUtils.isEmpty(token))
                throw new PtaiServerException("PT AI EE server returned empty API token");
            log.debug("PT AI EE JWT token is {}...", token.substring(0, 10));
        } catch (PtaiClientException e) {
            log.error(e.getMessage());
            log.trace("Exception details", e);
            res.ptai(ComponentStatus.FAILURE);
        }
        try {
            JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(
                    jenkinsClient, jenkinsClient.getMaxRetry(), jenkinsClient.getRetryDelay());
            ApiResponse<Void> jenkinsInfo = apiClient.callApi(
                    () -> jenkinsClient.getJenkinsApi().headJenkinsWithHttpInfo(),
                    "Getting embedded server version");
            Optional<String> jenkinsVersion = Optional.ofNullable(jenkinsInfo)
                    .map(info -> info.getHeaders())
                    .map(headers -> headers.get("X-Jenkins"))
                    .map(values -> values.stream().findFirst())
                    .orElseThrow(() -> new JenkinsClientException("No embedded server found"));
            if (!jenkinsVersion.isPresent())
                throw new PtaiServerException("Embedded server returned empty version number");
            log.debug("Embedded server version is {}", jenkinsVersion.get());
            String jobName = ApiClient.convertJobName(jenkinsClient.getCiJobName());
            FreeStyleProject prj = apiClient.callApi(
                    () -> jenkinsClient.getJenkinsApi().getJob(jobName),
                    "Checking build job");
            Integer buildNumber = prj.getNextBuildNumber();
            log.debug("Next SAST job build number is {}", buildNumber);
        } catch (JenkinsClientException e) {
            log.error(e.getMessage());
            log.trace("Exception details", e);
            res.embedded(ComponentStatus.FAILURE);
        }
        return res;
    }

    public List<Node> getAstNodes() {
        List<Node> res = new ArrayList<>();
        try {
            JenkinsApiClientWrapper apiClient = new JenkinsApiClientWrapper(
                    jenkinsClient, jenkinsClient.getMaxRetry(), jenkinsClient.getRetryDelay());
            ComputerSet nodes = apiClient.callApi(
                    () -> jenkinsClient.getJenkinsApi().getComputer(0),
                    "Getting list of AST nodes");
            Set<String> tags = new HashSet<>();
            for (HudsonMasterComputer node : nodes.getComputer()) {
                if (!"hudson.slaves.SlaveComputer".equalsIgnoreCase(node.getPropertyClass())) continue;
                node.getAssignedLabels()
                        .stream()
                        .filter(l -> !l.getName().equals(node.getDisplayName()))
                        .forEach(l -> tags.add(l.getName()));
                res.add(new Node().name(node.getDisplayName()).type(Node.TypeEnum.NAME));
            }
            tags.stream()
                    .distinct()
                    .forEach(t -> res.add(new Node().name(t).type(Node.TypeEnum.TAG)));
        } catch (JenkinsClientException e) {
            log.error(e.getMessage());
            log.trace("Exception details", e);
            return null;
        }
        return res;
    }
}
