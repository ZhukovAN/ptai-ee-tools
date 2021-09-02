package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.integration.rest.test.BaseIT;
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
        String scanResultStr = getResourceString("v36/json/scanResult/" + fileName + ".json");
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = mapper.readValue(scanResultStr, com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult.class);
        Map<Reports.Locale, InputStream> issuesModel = new HashMap<>();
        for (Reports.Locale locale : Reports.Locale.values()) {
            Path issuesFile = getPackedResourceFile("v36/json/issuesModel/" + fileName + "." + locale.getLocale().getLanguage() + ".json.7z");
            issuesModel.put(locale, new FileInputStream(issuesFile.toFile()));
        }

        @NonNull final V36ScanSettings scanSettings = mapper.readValue(
                getResourceString("v36/json/scanSettings/" + fileName + ".json"),
                V36ScanSettings.class
        );
        Map<ServerVersionTasks.Component, String> versions = new HashMap<>();
        versions.put(ServerVersionTasks.Component.AIE, "3.6.4.2843");
        versions.put(ServerVersionTasks.Component.AIC, "3.6.4.1437");

        String projectName = StringUtils.substringBefore(fileName, ".");

        ScanResult genericScanResult = IssuesConverter.convert(projectName, scanResult, issuesModel, scanSettings, BaseIT.URL, versions);
        for (InputStream issuesModelStream : issuesModel.values())
            issuesModelStream.close();
        return genericScanResult;
    }

    @Test
    @DisplayName("Convert OWASP Bricks scan results")
    @SneakyThrows
    public void generateOwaspBricksResultsV36() {
        ScanResult scanResult = generateScanResultV36("php-bricks");

        Path destination = Files.createTempFile(TEMP_FOLDER, "ptai-", "-scanResult");
        BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), scanResult);
    }

    @Test
    @DisplayName("Convert OWASP Benchmark scan results")
    @SneakyThrows
    public void generateOwaspBenchmarkResultsV36() {
        ScanResult scanResult = generateScanResultV36("java-owasp-benchmark");

        Path destination = Files.createTempFile(TEMP_FOLDER, "ptai-", "-scanResult");
        BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), scanResult);
    }

    @Test
    @DisplayName("Convert PHP Smoke scan results")
    @SneakyThrows
    public void generatePhpSmokeResultsV36() {
        ScanResult scanResult = generateScanResultV36("php-smoke");

        Path destination = Files.createTempFile(TEMP_FOLDER, "ptai-", "-scanResult");
        BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), scanResult);
    }
}
