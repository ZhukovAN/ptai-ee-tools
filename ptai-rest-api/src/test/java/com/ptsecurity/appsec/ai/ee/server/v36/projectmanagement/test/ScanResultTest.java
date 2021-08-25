package com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.test;

import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.JSON;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;

@DisplayName("Test base scan results data read and parse")
public class ScanResultTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from base OWASP Bricks scan results JSON resource file")
    public void parseRawBricksScanResults() {
        InputStream inputStream = getResourceStream("v36/json/scanResult/php-bricks.json");
        Assertions.assertNotNull(inputStream);
        try (InputStreamReader reader = new InputStreamReader(inputStream)) {
            ScanResult scanResult = new JSON().getGson().fromJson(reader, ScanResult.class);

            Assertions.assertNotNull(scanResult.getStatistic());
            Assertions.assertNotEquals(0, scanResult.getStatistic().getHighLevelVulnerabilityCount());
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from base PHP Smoke scan results JSON resource file")
    public void parseRawPhpSmokeScanResults() {
        InputStream inputStream = getResourceStream("v36/json/scanResult/php-smoke.json");
        Assertions.assertNotNull(inputStream);
        try (InputStreamReader reader = new InputStreamReader(inputStream)) {
            ScanResult scanResult = new JSON().getGson().fromJson(reader, ScanResult.class);

            Assertions.assertNotNull(scanResult.getStatistic());
            Assertions.assertEquals(1, scanResult.getStatistic().getMediumLevelVulnerabilityCount());
        }
    }
}
