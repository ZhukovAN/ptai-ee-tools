package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters.IssuesConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

@DisplayName("Test PT AI server REST API data structures conversion")
public class ConverterTest extends BaseTest {
    @SneakyThrows
    public ScanResult generateScanResultV36(@NonNull final String fileName) {
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        String scanResultStr = getResourceString("v36/json/scanResult/" + fileName);
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = mapper.readValue(scanResultStr, com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult.class);
        InputStream issuesModel = new FileInputStream(getPackedResourceFile("v36/json/issuesModel/" + fileName + ".7z").toFile());
        @NonNull final V36ScanSettings scanSettings = mapper.readValue(
                getResourceString("v36/json/scanSettings/" + fileName),
                V36ScanSettings.class
        );
        Map<ServerVersionTasks.Component, String> versions = new HashMap<>();
        versions.put(ServerVersionTasks.Component.AIE, "3.6.4.2843");
        versions.put(ServerVersionTasks.Component.AIC, "3.6.4.1437");

        String projectName = StringUtils.substringBefore(fileName, ".");

        ScanResult genericScanResult = IssuesConverter.convert(projectName, scanResult, issuesModel, scanSettings, versions);
        issuesModel.close();
        return genericScanResult;
    }

    @Test
    @DisplayName("Convert OWASP Bricks scan results")
    @SneakyThrows
    public void generateOwaspBricksResultsV36() {
        ScanResult scanResult = generateScanResultV36("php-bricks.raw.json");

        Path destination = Files.createTempFile(TEMP_FOLDER, "ptai-", "-scanResult");
        BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), scanResult);
        deleteFolder(TEMP_FOLDER);
    }

    @Test
    @DisplayName("Convert OWASP Benchmark scan results")
    @SneakyThrows
    public void generateOwaspBenchmarkResultsV36() {
        ScanResult scanResult = generateScanResultV36("java-owasp-benchmark.raw.json");

        Path destination = Files.createTempFile(TEMP_FOLDER, "ptai-", "-scanResult");
        BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), scanResult);
        deleteFolder(TEMP_FOLDER);
    }

    @Test
    @DisplayName("Convert PHP Smoke scan results")
    @SneakyThrows
    public void generatePhpSmokeResultsV36() {
        ScanResult scanResult = generateScanResultV36("php-smoke.raw.json");

        Path destination = Files.createTempFile(TEMP_FOLDER, "ptai-", "-scanResult");
        BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), scanResult);
        deleteFolder(TEMP_FOLDER);
    }
}
