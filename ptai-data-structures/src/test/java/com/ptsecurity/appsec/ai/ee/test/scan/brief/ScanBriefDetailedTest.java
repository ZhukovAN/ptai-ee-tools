package com.ptsecurity.appsec.ai.ee.test.scan.brief;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

@Slf4j
@DisplayName("Read and convert data from PT AI version-independent scan results JSON resource files")
public class ScanBriefDetailedTest extends BaseTest {
    @SneakyThrows
    protected ScanBriefDetailed parseScanResults(@NonNull final String projectName, @NonNull final Connection.Version version) {
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        String json = extractSevenZippedSingleStringFromResource("json/scan/result/" + version.name().toLowerCase()+ "/" + projectName + ".json.7z");
        ScanResult scanResult = mapper.readValue(json, ScanResult.class);
        return ScanBriefDetailed.create(scanResult, ScanBriefDetailed.Performance.builder().build());
    }

    @Test
    @DisplayName("Convert PT AI 4.1.1 and 4.2 scan results")
    @SneakyThrows
    public void generateScanResults() {
        try (TempFile temp = TempFile.createFolder()) {
            Path briefDetailed = temp.toPath().resolve("brief").resolve("detailed");
            briefDetailed.toFile().mkdirs();
            for (Connection.Version version : Connection.Version.values()) {
                Path destination = briefDetailed.resolve(version.name().toLowerCase());
                destination.toFile().mkdirs();
                for (String projectName : ALL_PROJECT_NAMES) {
                    ScanBriefDetailed scanBriefDetailed = parseScanResults(projectName, version);
                    String json = createFaultTolerantObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(scanBriefDetailed);
                    sevenZipData(destination.resolve(projectName + ".json.7z"), json.getBytes(StandardCharsets.UTF_8));
                    if (JAVA_OWASP_BENCHMARK_PROJECT_NAME.equals(projectName)) {
                        long sqliCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                                .filter(i -> BaseIssue.Level.HIGH == i.getLevel())
                                .filter(i -> "SQL Injection".equalsIgnoreCase(i.getTitle().get(Reports.Locale.EN))).count();
                        Assertions.assertNotEquals(0, sqliCount);
                    } else if (PHP_SMOKE_MEDIUM_PROJECT_NAME.equals(projectName)) {
                        long xssCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                                .filter(i -> BaseIssue.Level.MEDIUM == i.getLevel())
                                .filter(i -> "Cross-Site Scripting".equalsIgnoreCase(i.getTitle().get(Reports.Locale.EN))).count();
                        Assertions.assertNotEquals(0, xssCount);
                    } else if (PHP_OWASP_BRICKS_PROJECT_NAME.equals(projectName)) {
                        long sqliCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                                .filter(i -> BaseIssue.Level.HIGH == i.getLevel())
                                .filter(i -> "SQL Injection".equalsIgnoreCase(i.getTitle().get(Reports.Locale.EN))).count();
                        Assertions.assertNotEquals(0, sqliCount);
                    }
                }
            }
            log.trace("Scan results briefs are saved to {}", briefDetailed);
        }
    }
}
