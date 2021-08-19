package com.ptsecurity.appsec.ai.ee.test.scan.brief;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Path;

@DisplayName("Read and convert data from PT AI version-independent scan results JSON resource files")
public class ScanBriefDetailedTest extends BaseTest {

    @SneakyThrows
    public ScanBriefDetailed parseScanResults(@NonNull final String fileName) {
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        InputStream inputStream = getResourceStream("json/scan/result/" + fileName);
        Assertions.assertNotNull(inputStream);
        ScanResult scanResult = mapper.readValue(inputStream, ScanResult.class);
        return ScanBriefDetailed.create(scanResult, ScanBriefDetailed.Performance.builder().build());
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and convert data from PT AI version-independent OWASP Bricks scan results JSON resource file")
    public void parseBricksScanResults() {
        ScanBriefDetailed scanBriefDetailed = parseScanResults("php-bricks.json");
        // System.out.println(createFaultTolerantObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(scanBriefDetailed));
        Assertions.assertNotNull(scanBriefDetailed.getDetails());
        long sqliCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                .filter(i -> BaseIssue.Level.HIGH == i.getLevel())
                .filter(i -> "SQL Injection".equalsIgnoreCase(i.getTitle())).count();
        Assertions.assertNotEquals(0, sqliCount);
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and convert data from PT AI version-independent PHP Smoke scan results JSON resource file")
    public void parsePhpSmokeScanResults() {
        ScanBriefDetailed scanBriefDetailed = parseScanResults("php-smoke.json");
        // System.out.println(createFaultTolerantObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(scanBriefDetailed));
        Assertions.assertNotNull(scanBriefDetailed.getDetails());
        long xssCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                .filter(i -> BaseIssue.Level.MEDIUM == i.getLevel())
                .filter(i -> "Cross-Site Scripting".equalsIgnoreCase(i.getTitle())).count();
        Assertions.assertNotEquals(0, xssCount);
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and convert data from PT AI version-independent OWASP Benchmark scan results JSON resource file")
    public void parseOwaspBenchmarkScanResults() {
        Path packedFileContents = getPackedResourceFile("json/scan/result/java-owasp-benchmark.raw.json.7z");
        Assertions.assertNotNull(packedFileContents);
        try (TempFile jsonFile = new TempFile(packedFileContents)) {
            Assertions.assertTrue(jsonFile.toFile().isFile());
            ScanResult scanResult = createFaultTolerantObjectMapper().readValue(jsonFile.toFile(), ScanResult.class);
            ScanBriefDetailed scanBriefDetailed = ScanBriefDetailed.create(scanResult, ScanBriefDetailed.Performance.builder().build());
            Assertions.assertNotNull(scanBriefDetailed.getDetails());
            long sqliCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                    .filter(i -> BaseIssue.Level.HIGH == i.getLevel())
                    .filter(i -> "SQL Injection".equalsIgnoreCase(i.getTitle())).count();
            Assertions.assertNotEquals(0, sqliCount);
        }
    }
}
