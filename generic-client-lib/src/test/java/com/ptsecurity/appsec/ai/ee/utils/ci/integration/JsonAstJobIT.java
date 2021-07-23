package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Data;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.RawData;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.ConfigurationIssue;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.JsonAstJobSetupOperationsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import io.jsonwebtoken.lang.Assert;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;

@DisplayName("Test JSON-based AST")
@Tag("integration")
public class JsonAstJobIT extends BaseAstIT {
    @SuperBuilder
    public static class JsonAstJobImpl extends UiAstJobIT.UiAstJobImpl {
        protected String jsonSettings;

        protected String jsonPolicy;

        @Override
        protected void init() throws GenericException {
            astOps = TestAstOperations.builder()
                    .owner(this)
                    .sources(sources)
                    .build();
            fileOps = TestFileOperations.builder()
                    .owner(this)
                    .destination(destination)
                    .build();
            setupOps = JsonAstJobSetupOperationsImpl.builder()
                    .owner(this)
                    .jsonPolicy(jsonPolicy)
                    .jsonSettings(jsonSettings)
                    .build();
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Scan PHP smoke project with medium level vulnerabilities using JSON settings and policy")
    public void scanPhpSmoke() {
        Path sources = getPackedResourceFile("code/php-smoke-medium.7z");
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        String jsonSettings = getResourceString("json/scan/settings/settings.minimal.aiproj");
        Assertions.assertFalse(StringUtils.isEmpty(jsonSettings));

        AiProjScanSettings settings = JsonSettingsHelper.verify(jsonSettings);
        settings.setProjectName("junit-" + UUID.randomUUID());
        settings.setProgrammingLanguage(ScanBrief.ScanSettings.Language.PHP);
        settings.setScanAppType("PHP");
        settings.setIsUseEntryAnalysisPoint(true);
        settings.setIsUsePublicAnalysisMethod(true);
        jsonSettings = JsonSettingsHelper.serialize(settings);

        Reports reports = new Reports();

        Report report = new Report();
        report.setFormat(Report.Format.HTML);
        report.setFileName(UUID.randomUUID() + ".html");
        report.setLocale(EN);
        report.setTemplate(Report.DEFAULT_TEMPLATE_NAME.get(report.getLocale()));
        reports.getReport().add(report);

        Data data = new Data();
        data.setFormat(Data.Format.JSON);
        data.setFileName(UUID.randomUUID() + ".json");
        data.setLocale(EN);
        reports.getData().add(data);

        RawData rawData = new RawData();
        rawData.setFileName(UUID.randomUUID() + ".json");
        reports.getRaw().add(rawData);

        GenericAstJob astJob = JsonAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .failIfFailed(true)
                .failIfUnstable(false)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .reports(reports)
                .jsonSettings(jsonSettings)
                .build();
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
    }

    @SneakyThrows
    @Test
    @DisplayName("Compare PHP smoke project scan duration and results for full and incremental modes")
    public void compareFullAndIncremental() {

        Path sources = getPackedResourceFile("code/php-smoke-medium.7z");
        Path destinationFull = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        String jsonSettings = getResourceString("json/scan/settings/settings.minimal.aiproj");
        Assertions.assertFalse(StringUtils.isEmpty(jsonSettings));

        AiProjScanSettings settings = JsonSettingsHelper.verify(jsonSettings);
        settings.setProjectName("junit-" + UUID.randomUUID());
        settings.setProgrammingLanguage(ScanBrief.ScanSettings.Language.PHP);
        settings.setScanAppType("PHP");
        settings.setIsUseEntryAnalysisPoint(true);
        settings.setIsUsePublicAnalysisMethod(true);
        settings.setUseIncrementalScan(false);
        jsonSettings = JsonSettingsHelper.serialize(settings);

        Reports reports = new Reports();

        Report report = new Report();
        report.setFormat(Report.Format.HTML);
        report.setFileName(UUID.randomUUID() + ".html");
        report.setLocale(EN);
        report.setTemplate(Report.DEFAULT_TEMPLATE_NAME.get(report.getLocale()));
        reports.getReport().add(report);

        Data data = new Data();
        data.setFormat(Data.Format.JSON);
        data.setFileName(UUID.randomUUID() + ".json");
        data.setLocale(EN);
        reports.getData().add(data);

        RawData rawData = new RawData();
        rawData.setFileName(UUID.randomUUID() + ".json");
        reports.getRaw().add(rawData);

        GenericAstJob astJob = JsonAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .failIfFailed(true)
                .failIfUnstable(false)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destinationFull)
                .reports(reports)
                .jsonSettings(jsonSettings)
                .build();
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
        Duration durationFull = Duration.parse(astJob.getScanBrief().getStatistic().getScanDurationIso8601());

        Path destinationIncremental = Files.createTempDirectory(TEMP_FOLDER, "ptai-");
        settings.setUseIncrementalScan(true);
        jsonSettings = JsonSettingsHelper.serialize(settings);
        astJob = JsonAstJobImpl.builder()
                .async(false)
                .fullScanMode(false)
                .failIfFailed(true)
                .failIfUnstable(false)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destinationIncremental)
                .reports(reports)
                .jsonSettings(jsonSettings)
                .build();
        res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
        Duration durationIncremental = Duration.parse(astJob.getScanBrief().getStatistic().getScanDurationIso8601());

        Assertions.assertTrue(0 < durationFull.compareTo(durationIncremental));
    }

    @SneakyThrows
    public ScanResult analyseMiscScanResults(@NonNull final Consumer<AiProjScanSettings> modifySettings) {
        Path sources = getPackedResourceFile("code/php-smoke-misc.7z");
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        String jsonSettings = getResourceString("json/scan/settings/settings.minimal.aiproj");
        Assertions.assertFalse(StringUtils.isEmpty(jsonSettings));

        AiProjScanSettings settings = JsonSettingsHelper.verify(jsonSettings);
        settings.setProjectName("junit-" + UUID.randomUUID());
        settings.setProgrammingLanguage(ScanBrief.ScanSettings.Language.PHP);
        modifySettings.accept(settings);
        jsonSettings = JsonSettingsHelper.serialize(settings);

        Reports reports = new Reports();
        RawData rawData = new RawData();
        rawData.setFileName(UUID.randomUUID() + ".json");
        reports.getRaw().add(rawData);

        GenericAstJob astJob = JsonAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .failIfFailed(true)
                .failIfUnstable(false)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .reports(reports)
                .jsonSettings(jsonSettings)
                .build();
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);

        File json = destination.resolve(rawData.getFileName()).toFile();
        Assertions.assertTrue(json.exists());
        ScanResult scanResult = BaseJsonHelper.createObjectMapper().readValue(json, ScanResult.class);
        return scanResult;
    }

    @SneakyThrows
    @Test
    @DisplayName("Check PHP smoke miscellaneous project scan results contain low level vulnerabilities only")
    public void checkLowLevelVulnerabilitiesOnly() {
        ScanResult scanResult = analyseMiscScanResults((settings) -> {
            settings.setScanAppType("Configuration");
            settings.setIsUseEntryAnalysisPoint(true);
        });
        Assertions.assertNotNull(scanResult);
        long lowLevelCount = scanResult.getIssues().stream()
                .filter(i -> i instanceof ConfigurationIssue)
                .map(i -> (ConfigurationIssue) i)
                .filter(c -> BaseIssue.Level.LOW == c.getLevel()).count();
        Assertions.assertEquals(scanResult.getIssues().size(), lowLevelCount);
    }
}
