package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.api.ProjectsApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.AuthScopeType;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.IssuesModel;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Stage;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.BaseJsonHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.IssuesModelHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
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

    @SneakyThrows
    protected ScanResult getLastScanResult(@NonNull final String projectName) {
        List<com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Project> projects = projectsApi.apiProjectsGet(true);
        com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Project project = projects.stream().filter(p -> projectName.equalsIgnoreCase(p.getName())).findAny().orElse(null);
        if (null == project) return null;
        List<ScanResult> projectScanResults = projectsApi.apiProjectsProjectIdScanResultsGet(project.getId(), AuthScopeType.ACCESSTOKEN);
        if (null == projectScanResults || projectScanResults.isEmpty()) return null;
        projectScanResults.sort(Comparator.comparing(ScanResult::getScanDate).reversed());
        return projectScanResults.get(0);
    }

    @SneakyThrows
    protected IssuesModel getLastScanResultIssues(@NonNull final String projectName) {
        ScanResult scanResult = getLastScanResult(projectName);
        if (null == scanResult) return null;
        File json = projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(scanResult.getProjectId(), scanResult.getId(), null);
        IssuesModel issues = IssuesModelHelper.parse(new FileInputStream(json));
        Base.callApi(
                json::delete,
                "Temporal file " + json.getPath() + " delete failed", true);
        return issues;
    }

    @Test
    @DisplayName("Save PHP-SMOKE project scan results to temporal file")
    @Tag("integration")
    @SneakyThrows
    public void savePhpSmokeScanResults() {
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();

        ScanResult scanResult = getLastScanResult("php-smoke");
        IssuesModel issuesModel = getLastScanResultIssues("php-smoke");

        try (TempFile outputScanResult = TempFile.createFile(TEMP_FOLDER); TempFile output = TempFile.createFile(TEMP_FOLDER)) {
            mapper.writerWithDefaultPrettyPrinter().writeValue(outputScanResult.getFile().toFile(), scanResult);
            mapper.writerWithDefaultPrettyPrinter().writeValue(output.getFile().toFile(), issuesModel);
        }
    }
}
