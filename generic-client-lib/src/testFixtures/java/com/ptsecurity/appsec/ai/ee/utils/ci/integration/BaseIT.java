package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanAgentApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanApi;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.ScanType;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.StartScanModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.CertificateHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ProgrammingLanguageHelper;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.LogManager;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


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
        List<com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Project> projects = projectsApi.apiProjectsGet(true);
        for (com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Project project : projects) {
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
