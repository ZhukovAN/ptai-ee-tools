package com.ptsecurity.appsec.ai.ee.test.scan.result;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

@DisplayName("Read and parse data from PT AI version-independent scan results JSON resource file")
public class ScanResultTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from PT AI version-independent OWASP Bricks scan results JSON resource file")
    public void parseBricksScanResults() {
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        InputStream inputStream = getResourceStream("json/scan/result/php-bricks.json");
        Assertions.assertNotNull(inputStream);
        ScanResult scanResult = mapper.readValue(inputStream, ScanResult.class);
        Assertions.assertNotNull(scanResult.getStatistic());
        Assertions.assertNotEquals(0, scanResult.getStatistic().getScannedFileCount());
        long sqliCount = scanResult.getIssues().stream()
                .filter(baseIssue -> baseIssue instanceof VulnerabilityIssue)
                .filter(baseIssue -> BaseIssue.Level.HIGH == baseIssue.getLevel())
                .filter(baseIssue -> "SQL Injection".equalsIgnoreCase(baseIssue.getTitle()))
                .count();
        Assertions.assertNotEquals(0, sqliCount);
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from PT AI version-independent PHP Smoke scan results JSON resource file")
    public void parsePhpSmokeScanResults() {
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        InputStream inputStream = getResourceStream("json/scan/result/php-smoke.json");
        Assertions.assertNotNull(inputStream);
        ScanResult scanResult = mapper.readValue(inputStream, ScanResult.class);
        Assertions.assertNotNull(scanResult.getStatistic());
        Assertions.assertNotEquals(0, scanResult.getStatistic().getScannedFileCount());
        long sqliCount = scanResult.getIssues().stream()
                .filter(baseIssue -> baseIssue instanceof VulnerabilityIssue)
                .filter(baseIssue -> BaseIssue.Level.MEDIUM == baseIssue.getLevel())
                .filter(baseIssue -> "Cross-Site Scripting".equalsIgnoreCase(baseIssue.getTitle()))
                .count();
        Assertions.assertEquals(1, sqliCount);
    }

}
