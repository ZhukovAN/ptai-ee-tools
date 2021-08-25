package com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.test;

import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.JSON;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ProgrammingLanguage;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;

@DisplayName("Test scan settings data read and parse")
public class ScanSettingsTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from base OWASP Bricks scan settings JSON resource file")
    public void parseRawBricksScanSettings() {
        InputStream inputStream = getResourceStream("v36/json/scanSettings/php-bricks.json");
        Assertions.assertNotNull(inputStream);
        try (InputStreamReader reader = new InputStreamReader(inputStream)) {
            V36ScanSettings scanResult = new JSON().getGson().fromJson(reader, V36ScanSettings.class);

            Assertions.assertNotNull(scanResult);
            Assertions.assertEquals(V36ProgrammingLanguage.PHP, scanResult.getProgrammingLanguage());
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from base PHP Smoke scan settings JSON resource file")
    public void parseRawPhpSmokeScanSettings() {
        InputStream inputStream = getResourceStream("v36/json/scanSettings/php-smoke.json");
        Assertions.assertNotNull(inputStream);
        try (InputStreamReader reader = new InputStreamReader(inputStream)) {
            V36ScanSettings scanResult = new JSON().getGson().fromJson(reader, V36ScanSettings.class);

            Assertions.assertNotNull(scanResult);
            Assertions.assertEquals(V36ProgrammingLanguage.PHP, scanResult.getProgrammingLanguage());
        }
    }
}
