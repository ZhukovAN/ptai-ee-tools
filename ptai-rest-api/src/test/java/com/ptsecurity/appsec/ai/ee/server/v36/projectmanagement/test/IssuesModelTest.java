package com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.test;

import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.JSON;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.IssuesModel;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36VulnerabilityIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.FileReader;
import java.nio.file.Path;

@DisplayName("Test issues model data read and parse")
public class IssuesModelTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from raw OWASP Bricks issues model 7zip-packed JSON resource file")
    public void parseRawBricksIssuesModel() {
        Path packedFileContents = extractPackedResourceFile("v36/json/issuesModel/" + PHP_OWASP_BRICKS_PROJECT_NAME + ".en.json.7z");
        Assertions.assertNotNull(packedFileContents);
        try (TempFile jsonFile = new TempFile(packedFileContents)) {
            Assertions.assertTrue(jsonFile.toFile().isFile());
            try (FileReader reader = new FileReader(jsonFile.toFile())) {
                IssuesModel issuesModel = new JSON().getGson().fromJson(reader, IssuesModel.class);

                Assertions.assertNotNull(issuesModel.getIssues());
                Assertions.assertNotEquals(0, issuesModel.getIssues().size());

                Assertions.assertNotNull(issuesModel.getDescriptions());
                Assertions.assertNotEquals(0, issuesModel.getDescriptions().size());

                Assertions.assertNotNull(issuesModel.getMetadatas());
                Assertions.assertNotEquals(0, issuesModel.getMetadatas().size());
            }
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from raw PHP Smoke issues model 7zip-packed JSON resource file")
    public void parseRawPhpSmokeIssuesModel() {
        Path packedFileContents = extractPackedResourceFile("v36/json/issuesModel/" + PHP_SMOKE_MEDIUM_PROJECT_NAME + ".en.json.7z");
        Assertions.assertNotNull(packedFileContents);
        try (TempFile jsonFile = new TempFile(packedFileContents)) {
            Assertions.assertTrue(jsonFile.toFile().isFile());
            try (FileReader reader = new FileReader(jsonFile.toFile())) {
                IssuesModel issuesModel = new JSON().getGson().fromJson(reader, IssuesModel.class);

                Assertions.assertNotNull(issuesModel.getIssues());
                Assertions.assertNotEquals(0, issuesModel.getIssues().size());

                Assertions.assertNotNull(issuesModel.getDescriptions());
                Assertions.assertNotEquals(0, issuesModel.getDescriptions().size());

                Assertions.assertNotNull(issuesModel.getMetadatas());
                Assertions.assertNotEquals(0, issuesModel.getMetadatas().size());

                Assertions.assertNotEquals(0, issuesModel.getIssues().size());

                boolean echoXss = issuesModel.getIssues().stream()
                        .filter(i -> i.getType().equalsIgnoreCase("Cross-site Scripting"))
                        .filter(xss -> xss instanceof V36VulnerabilityIssue)
                        .map(xss -> (V36VulnerabilityIssue) xss)
                        .anyMatch(xss -> "echo".equals(xss.getFunction()));
                Assertions.assertTrue(echoXss);
            }
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from raw OWASP Benchmark issues model 7zip-packed JSON resource file")
    public void parseRawOwaspBenchmarkIssuesModel() {
        Path packedFileContents = extractPackedResourceFile("v36/json/issuesModel/" + JAVA_OWASP_BENCHMARK_PROJECT_NAME + ".en.json.7z");
        Assertions.assertNotNull(packedFileContents);
        try (TempFile jsonFile = new TempFile(packedFileContents)) {
            Assertions.assertTrue(jsonFile.toFile().isFile());
            try (FileReader reader = new FileReader(jsonFile.toFile())) {
                IssuesModel issuesModel = new JSON().getGson().fromJson(reader, IssuesModel.class);

                Assertions.assertNotNull(issuesModel.getIssues());
                Assertions.assertNotEquals(0, issuesModel.getIssues().size());

                Assertions.assertNotNull(issuesModel.getDescriptions());
                Assertions.assertNotEquals(0, issuesModel.getDescriptions().size());

                Assertions.assertNotNull(issuesModel.getMetadatas());
                Assertions.assertNotEquals(0, issuesModel.getMetadatas().size());
            }
        }
    }

}
