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
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

@Slf4j
@DisplayName("Read and convert data from PT AI version-independent scan results JSON resource files")
public class ScanBriefDetailedTest extends BaseTest {

    @SneakyThrows
    public ScanBriefDetailed parseScanResults(@NonNull final String projectName, @NonNull final Connection.Version version) {
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        String json = extractSevenZippedSingleStringFromResource("json/scan/result/" + version.name().toLowerCase()+ "/" + projectName + ".json.7z");
        ScanResult scanResult = mapper.readValue(json, ScanResult.class);
        return ScanBriefDetailed.create(scanResult, ScanBriefDetailed.Performance.builder().build());
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and convert data from PT AI version-independent OWASP Bricks scan results JSON resource file")
    public void parseBricksScanResults() {
        for (Connection.Version version : Connection.Version.values())
            parseBricksScanResults(version);
    }

    @SneakyThrows
    public void parseBricksScanResults(@NonNull final Connection.Version version) {
        ScanBriefDetailed scanBriefDetailed = parseScanResults(PHP_OWASP_BRICKS_PROJECT_NAME, version);
        // System.out.println(createFaultTolerantObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(scanBriefDetailed));
        Assertions.assertNotNull(scanBriefDetailed.getDetails());
        long sqliCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                .filter(i -> BaseIssue.Level.HIGH == i.getLevel())
                .filter(i -> "SQL Injection".equalsIgnoreCase(i.getTitle().get(Reports.Locale.EN))).count();
        Assertions.assertNotEquals(0, sqliCount);
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and convert data from PT AI version-independent PHP Smoke scan results JSON resource file")
    public void parsePhpSmokeMediumScanResults() {
        for (Connection.Version version : Connection.Version.values())
            parsePhpSmokeMediumScanResults(version);
    }

    @SneakyThrows
    public void parsePhpSmokeMediumScanResults(@NonNull final Connection.Version version) {
        ScanBriefDetailed scanBriefDetailed = parseScanResults(PHP_SMOKE_MEDIUM_PROJECT_NAME, version);
        // System.out.println(createFaultTolerantObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(scanBriefDetailed));
        Assertions.assertNotNull(scanBriefDetailed.getDetails());
        long xssCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                .filter(i -> BaseIssue.Level.MEDIUM == i.getLevel())
                .filter(i -> "Cross-Site Scripting".equalsIgnoreCase(i.getTitle().get(Reports.Locale.EN))).count();
        Assertions.assertNotEquals(0, xssCount);
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and convert data from PT AI version-independent OWASP Benchmark scan results JSON resource file")
    public void parseOwaspBenchmarkScanResults() {
        for (Connection.Version version : Connection.Version.values()) {
            Path packedFileContents = extractPackedResourceFile("json/scan/result/" + version.name().toLowerCase() + "/" + JAVA_OWASP_BENCHMARK_PROJECT_NAME + ".json.7z");
            Assertions.assertNotNull(packedFileContents);
            try (TempFile jsonFile = new TempFile(packedFileContents)) {
                Assertions.assertTrue(jsonFile.toFile().isFile());
                ScanResult scanResult = createFaultTolerantObjectMapper().readValue(jsonFile.toFile(), ScanResult.class);
                ScanBriefDetailed scanBriefDetailed = ScanBriefDetailed.create(scanResult, ScanBriefDetailed.Performance.builder().build());
                Assertions.assertNotNull(scanBriefDetailed.getDetails());
                long sqliCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                        .filter(i -> BaseIssue.Level.HIGH == i.getLevel())
                        .filter(i -> "SQL Injection".equalsIgnoreCase(i.getTitle().get(Reports.Locale.EN))).count();
                Assertions.assertNotEquals(0, sqliCount);
            }
        }
    }

    @Test
    @DisplayName("Convert PT AI 3.6, 4.0, 4.1 and 4.1.1 scan results")
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
                    // FileUtils.writeStringToFile(destination.resolve(projectName + ".json").toFile(), json, StandardCharsets.UTF_8);
                }
            }
            log.trace("Scan results briefs are saved to {}", briefDetailed);
        }
    }
}
