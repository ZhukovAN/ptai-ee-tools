package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export;

import com.contrastsecurity.sarif.SarifSchema210;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.ConverterTest;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.getTemplate;

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
        ScanResult scanResult = generateScanResultV411(getTemplate(ProjectTemplate.ID.PHP_SMOKE).getName());

        SarifSchema210 sarif = Sarif.convert(scanResult, true);

        String sarifStr = BaseJsonHelper.serialize(sarif);
        JsonNode root = new ObjectMapper().readTree(sarifStr);
    }
}