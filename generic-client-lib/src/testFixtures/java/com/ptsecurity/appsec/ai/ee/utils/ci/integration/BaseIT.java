package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.api.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.AuthScopeType;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Stage;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;


public class BaseIT extends BaseTest {
    protected static String TOKEN = (null != System.getenv("ptai.token")) ? System.getenv("ptai.token") : "6M9Qsct5fg20/UEzN7/hvR2RlXkTWOI5";
    protected static String URL = (null != System.getenv("ptai.url")) ? System.getenv("ptai.url") : "https://ptai.domain.org:443/";
    protected BaseClient client = null;
    protected ProjectsApi projectsApi = null;

    @SneakyThrows
    @BeforeEach
    public void pre() {
        client = new BaseClient();
        client.setUrl(URL);
        client.setToken(TOKEN);
        client.setCaCertsPem(PEM);
        client.init();

        projectsApi = client.getProjectsApi();
    }

    @AfterEach
    public void post() throws IOException {
        client = null;
    }

    protected com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project createProject(@NonNull final String name) {
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project project = Project.builder()
                .name(name)
                .url(client.getUrl())
                .token(client.getToken())
                .caCertsPem(client.getCaCertsPem()).build();
        project.init();
        return project;
    }

    protected Utils createUtils() {
        Utils utils = new Utils();
        utils.setUrl(client.getUrl());
        utils.setToken(client.getToken());
        utils.setCaCertsPem(client.getCaCertsPem());
        utils.init();
        return utils;
    }

    @SneakyThrows
    protected ScanResult getRandomScanResult() {
        List<ScanResult> res = new ArrayList<>();
        List<com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Project> projects = projectsApi.apiProjectsGet(true);
        for (com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Project project : projects) {
            List<ScanResult> projectScanResults = projectsApi.apiProjectsProjectIdScanResultsGet(project.getId(), AuthScopeType.ACCESSTOKEN);
            projectScanResults.stream()
                    .filter(r -> r.getProgress().getStage().equals(Stage.DONE))
                    .filter(r -> 0 != r.getStatistic().getTotalVulnerabilityCount())
                    .forEach(r -> res.add(r));
        }
        Assertions.assertFalse(res.isEmpty(), "Scan results not found");
        return res.get(new Random().nextInt(res.size()));
    }

}
