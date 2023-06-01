package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v430;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.server.v430.api.model.ScanResultModel;
import com.ptsecurity.appsec.ai.ee.server.v430.api.model.ScanSettingsModel;
import com.ptsecurity.appsec.ai.ee.server.v430.api.model.VulnerabilityModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.getTemplate;
import static com.ptsecurity.misc.tools.helpers.ArchiveHelper.extractResourceFile;
import static com.ptsecurity.misc.tools.helpers.ArchiveHelper.packData7Zip;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
@DisplayName("Test PT AI server REST API data structures conversion")
public class ConverterTest extends BaseTest {
    @SneakyThrows
    public ScanResult generateScanResultV430(@NonNull final String fileName) {
        ObjectMapper mapper = createObjectMapper();
        log.trace("Read scan results");
        String scanResultStr = getResourceString("v430/json/scanResult/" + fileName + ".json");
        ScanResultModel scanResult = mapper.readValue(scanResultStr, ScanResultModel.class);
        log.trace("Read scan issues");
        String scanIssuesStr = getResourceString("v430/json/issuesModel/" + fileName + ".json");
        TypeReference<List<VulnerabilityModel>> typeRef = new TypeReference<List<VulnerabilityModel>>() {};
        List<VulnerabilityModel> issues = mapper.readValue(scanIssuesStr, typeRef);
        log.trace("Read localized scan issues headers");
        Map<Reports.Locale, Map<String, String>> issuesHeadersFiles = new HashMap<>();
        for (Reports.Locale locale : Reports.Locale.values()) {
            Path issuesFile = extractResourceFile("v430/json/issuesModel/" + fileName + "." + locale.getLocale().getLanguage() + ".json.7z");
            TypeReference<Map<String, String>> mapTypeRef = new TypeReference<Map<String, String>>() {};
            Map<String, String> localizedIssuesHeaders = mapper.readValue(issuesFile.toFile(), mapTypeRef);
            issuesHeadersFiles.put(locale, localizedIssuesHeaders);
        }

        @NonNull final ScanSettingsModel scanSettings = mapper.readValue(
                getResourceString("v430/json/scanSettings/" + fileName + ".json"),
                ScanSettingsModel.class
        );
        Map<ServerVersionTasks.Component, String> versions = new HashMap<>();
        versions.put(ServerVersionTasks.Component.AIE, "4.3.0.22105");
        versions.put(ServerVersionTasks.Component.AIC, "4.3.0.22105");

        String projectName = StringUtils.substringBefore(fileName, ".");

        return com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v430.converters.IssuesConverter.convert(projectName, scanResult, issues, issuesHeadersFiles, scanSettings, "https://ptai430.domain.org", versions);
    }

    @Test
    @DisplayName("Convert PT AI 4.3 scan results")
    @SneakyThrows
    public void generateScanResults() {
        try (TempFile destination = TempFile.createFolder()) {
            Path scanResults430 = destination.toPath().resolve("result").resolve("v430");
            assertTrue(scanResults430.toFile().mkdirs());

            for (ProjectTemplate.ID templateId : ProjectTemplate.ID.values()) {
                ProjectTemplate projectTemplate = getTemplate(templateId);
                ScanResult scanResult = generateScanResultV430(projectTemplate.getName());
                String json = BaseJsonHelper.minimize(scanResult);
                packData7Zip(scanResults430.resolve(projectTemplate.getName() + ".json.7z"), json.getBytes(StandardCharsets.UTF_8));
            }
            log.trace("Scan results are saved to {}", destination);
        }
    }
}
