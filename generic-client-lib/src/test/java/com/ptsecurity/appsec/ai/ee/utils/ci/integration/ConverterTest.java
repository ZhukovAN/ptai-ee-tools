package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.V40ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters.IssuesConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.*;

@Slf4j
@DisplayName("Test PT AI server REST API data structures conversion")
public class ConverterTest extends BaseTest {
    @SneakyThrows
    public ScanResult generateScanResultV36(@NonNull final String fileName) {
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        String scanResultStr = getResourceString("v36/json/scanResult/" + fileName + ".json");
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = mapper.readValue(scanResultStr, com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult.class);
        Map<Reports.Locale, InputStream> issuesModel = new HashMap<>();
        for (Reports.Locale locale : Reports.Locale.values()) {
            Path issuesFile = extractPackedResourceFile("v36/json/issuesModel/" + fileName + "." + locale.getLocale().getLanguage() + ".json.7z");
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

        ScanResult genericScanResult = IssuesConverter.convert(projectName, scanResult, issuesModel, scanSettings, CONNECTION().getUrl(), versions);
        for (InputStream issuesModelStream : issuesModel.values())
            issuesModelStream.close();
        return genericScanResult;
    }

    @SneakyThrows
    public ScanResult generateScanResultV40(@NonNull final String fileName) {
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        String scanResultStr = getResourceString("v40/json/scanResult/" + fileName + ".json");
        com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.ScanResult scanResult = mapper.readValue(scanResultStr, com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.ScanResult.class);
        Map<Reports.Locale, InputStream> issuesModel = new HashMap<>();
        for (Reports.Locale locale : Reports.Locale.values()) {
            Path issuesFile = extractPackedResourceFile("v40/json/issuesModel/" + fileName + "." + locale.getLocale().getLanguage() + ".json.7z");
            issuesModel.put(locale, new FileInputStream(issuesFile.toFile()));
        }

        @NonNull final V40ScanSettings scanSettings = mapper.readValue(
                getResourceString("v40/json/scanSettings/" + fileName + ".json"),
                V40ScanSettings.class
        );
        Map<ServerVersionTasks.Component, String> versions = new HashMap<>();
        versions.put(ServerVersionTasks.Component.AIE, "4.0.0.9172");
        versions.put(ServerVersionTasks.Component.AIC, "4.0.0.9172");

        String projectName = StringUtils.substringBefore(fileName, ".");

        ScanResult genericScanResult = com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.converters.IssuesConverter.convert(projectName, scanResult, issuesModel, scanSettings, CONNECTION().getUrl(), versions);
        for (InputStream issuesModelStream : issuesModel.values())
            issuesModelStream.close();
        return genericScanResult;
    }

    @Test
    @DisplayName("Convert OWASP Bricks PT AI 3.6 scan results")
    @SneakyThrows
    public void generateOwaspBricksResultsV36() {
        ScanResult scanResult = generateScanResultV36(PHP_OWASP_BRICKS.getName());
        Assertions.assertTrue(scanResult.getIssues().stream()
                .map(issue -> scanResult.getI18n().get(issue.getTypeId()).get(Reports.Locale.EN).getTitle())
                .anyMatch(title -> title.equals("Cross-Site Scripting")));

        Path destination = Files.createTempFile(TEMP_FOLDER(), "ptai-", "-scanResult");
        BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), scanResult);
    }

    @Test
    @DisplayName("Convert PT AI 3.6 and 4.0 scan results")
    @SneakyThrows
    public void generateScanResults() {
        try (TempFile destination = TempFile.createFolder()) {
            Path scanResults36 = destination.toPath().resolve("result").resolve("v36");
            scanResults36.toFile().mkdirs();
            Path scanResults40 = destination.toPath().resolve("result").resolve("v40");
            scanResults40.toFile().mkdirs();

            for (Project project : ALL) {
                ScanResult scanResult = generateScanResultV36(project.getName());
                String json = BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(scanResult);
                sevenZipData(scanResults36.resolve(project.getName() + ".json.7z"), json.getBytes(StandardCharsets.UTF_8));

                scanResult = generateScanResultV40(project.getName());
                json = BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(scanResult);
                sevenZipData(scanResults40.resolve(project.getName() + ".json.7z"), json.getBytes(StandardCharsets.UTF_8));
            }
            log.trace("Scan results are saved to {}", scanResults36);
        }
    }
}
