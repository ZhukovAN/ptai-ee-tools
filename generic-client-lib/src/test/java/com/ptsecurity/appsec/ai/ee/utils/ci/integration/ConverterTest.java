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
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class ConverterTest extends BaseTest {
    @Test
    @SneakyThrows
    public void generateOwaspBricksResultsV36() {
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        String scanResultStr = getResourceString("v36/json/scanResult/java-owasp-benchmark.raw.json");
        com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult = mapper.readValue(scanResultStr, com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult.class);
        InputStream issuesModel = new FileInputStream(getPackedResourceFile("v36/json/issuesModel/java-owasp-benchmark.raw.json.7z").toFile());
        @NonNull final V36ScanSettings scanSettings = mapper.readValue(
                getResourceString("v36/json/scanSettings/java-owasp-benchmark.raw.json"),
                V36ScanSettings.class
        );
        Map<ServerVersionTasks.Component, String> versions = new HashMap<>();
        versions.put(ServerVersionTasks.Component.AIE, "3.6.4.2843");
        versions.put(ServerVersionTasks.Component.AIC, "3.6.4.1437");

        ScanResult genericScanResult = IssuesConverter.convert(UUID.randomUUID().toString(), scanResult, issuesModel, scanSettings, versions);
        issuesModel.close();

        Path destination = Files.createTempFile(TEMP_FOLDER, "ptai-", "-scanResult");
        mapper.writerWithDefaultPrettyPrinter().writeValue(destination.toFile(), genericScanResult);
        deleteFolder(TEMP_FOLDER);
    }
}
