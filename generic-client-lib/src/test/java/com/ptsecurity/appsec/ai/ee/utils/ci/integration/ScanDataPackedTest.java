package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.helpers.ArchiveHelper;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Testing packed scan data processing")
public class ScanDataPackedTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Packing detailed scan briefs")
    public void packOwaspBenchmarksScanBriefDetailed() {
        for (ApiVersion version : ApiVersion.values()) {
            if (version.isDeprecated()) continue;
            for (Project project : Project.ALL) {
                File scanBriefDetailedFile = ArchiveHelper.extractResourceFile("json/scan/brief/detailed/" + version.name().toLowerCase() + "/" + project.getName() + ".json.7z").toFile();
                ObjectMapper mapper = createObjectMapper();
                ScanBriefDetailed scanBriefDetailed = mapper.readValue(scanBriefDetailedFile, ScanBriefDetailed.class);
                String unpackedData = mapper.writeValueAsString(scanBriefDetailed);
                assertTrue(StringUtils.isNotEmpty(unpackedData));
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
