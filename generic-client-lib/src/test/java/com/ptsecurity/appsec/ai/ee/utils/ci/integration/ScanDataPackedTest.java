package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;

@DisplayName("Testing packed scan data processing")
public class ScanDataPackedTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Packing detailed scan briefs")
    public void packOwaspBenchmarksScanBriefDetailed() {
        for (Connection.Version version : Connection.Version.values()) {
            for (String projectName : ALL_PROJECT_NAMES) {
                File scanBriefDetailedFile = extractPackedResourceFile("json/scan/brief/detailed/" + version.name().toLowerCase() + "/" + projectName + ".json.7z").toFile();
                ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
                ScanBriefDetailed scanBriefDetailed = mapper.readValue(scanBriefDetailedFile, ScanBriefDetailed.class);
                String unpackedData = mapper.writeValueAsString(scanBriefDetailed);
                ScanDataPacked packedData = ScanDataPacked.builder()
                        .type(ScanDataPacked.Type.SCAN_BRIEF_DETAILED)
                        .data(ScanDataPacked.packData(scanBriefDetailed))
                        .build();

                ScanBriefDetailed scanBriefDetailedExtracted = ScanDataPacked.unpackData(packedData.getData(), ScanBriefDetailed.class);

                Assertions.assertEquals(
                        scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().size(),
                        scanBriefDetailedExtracted.getDetails().getChartData().getBaseIssueDistributionData().size());
            }
        }
    }
}
