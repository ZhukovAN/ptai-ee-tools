package com.ptsecurity.appsec.ai.ee.scan.brief;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate;
import com.ptsecurity.misc.tools.helpers.ArchiveHelper;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import com.ptsecurity.misc.tools.TempFile;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.ID.*;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.serialize;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
@DisplayName("Read and convert data from PT AI version-independent scan results JSON resource files")
public class ScanBriefDetailedTest extends BaseTest {
    @SneakyThrows
    protected ScanBriefDetailed parseScanResults(@NonNull final String projectName, @NonNull final ScanBrief.ApiVersion version) {
        String json = ResourcesHelper.getResource7ZipString("json/scan/result/" + version.name().toLowerCase()+ "/" + projectName + ".json.7z");
        ScanResult scanResult = createObjectMapper().readValue(json, ScanResult.class);
        return ScanBriefDetailed.create(scanResult, ScanBriefDetailed.Performance.builder().build());
    }

    @Test
    @DisplayName("Convert PT AI 4.1.1, 4.2.0, 4.3.0, 4.4.1, 4.5.0, 4.6.0, 4.7.0 scan results")
    @SneakyThrows
    public void generateScanResults() {
        try (TempFile temp = TempFile.createFolder()) {
            Path briefDetailed = temp.toPath().resolve("brief").resolve("detailed");
            assertTrue(briefDetailed.toFile().mkdirs());
            for (ScanBrief.ApiVersion version : ScanBrief.ApiVersion.values()) {
                if (version.isDeprecated()) continue;
                Path destination = briefDetailed.resolve(version.name().toLowerCase());
                assertTrue(destination.toFile().mkdirs());
                for (ProjectTemplate.ID templateId : ID.values()) {
                    ProjectTemplate projectTemplate = getTemplate(templateId);
                    ScanBriefDetailed scanBriefDetailed = parseScanResults(projectTemplate.getName(), version);
                    String json = serialize(scanBriefDetailed);
                    ArchiveHelper.packData7Zip(destination.resolve(projectTemplate.getName() + ".json.7z"), json);
                    if (JAVA_OWASP_BENCHMARK == templateId) {
                        long sqliCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                                .filter(i -> BaseIssue.Level.HIGH == i.getLevel())
                                .filter(i -> "SQL Injection".equalsIgnoreCase(i.getTitle().get(Reports.Locale.EN))).count();
                        Assertions.assertNotEquals(0, sqliCount);
                    } else if (PHP_SMOKE.equals(templateId)) {
                        long xssCount = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().stream()
                                .filter(i -> BaseIssue.Level.MEDIUM == i.getLevel())
                                .filter(i -> "Cross-Site Scripting".equalsIgnoreCase(i.getTitle().get(Reports.Locale.EN))).count();
                        Assertions.assertNotEquals(0, xssCount);
                    } else if (PHP_OWASP_BRICKS.equals(templateId)) {
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
