package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export;

import com.contrastsecurity.sarif.SarifSchema210;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ConverterTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.PHP_SMOKE_MULTIFLOW;

@DisplayName("Test SARIF report generation")
public class SarifTest extends ConverterTest {
    /**
     *
     */
    @SneakyThrows
    @Test
    @DisplayName("Generate multiflow SARIF report")
    public void generateMultiflowReport() {
        boolean processGroups = false;
        ScanResult scanResult = generateScanResultV411(PHP_SMOKE_MULTIFLOW.getName());

        SarifSchema210 sarif = Sarif.convert(scanResult, true);

        String sarifStr = BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(sarif);
        JsonNode root = new ObjectMapper().readTree(sarifStr);
    }
}