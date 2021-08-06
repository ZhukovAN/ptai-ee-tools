package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Data;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.RawData;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.UiAstJobSetupOperationsImpl;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;

@DisplayName("Test UI-based AST")
@Tag("integration")
public class UiAstJobIT extends BaseAstIT {
    @SuperBuilder
    public static class UiAstJobImpl extends GenericAstJob {
        protected Path sources;

        protected Path destination;

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
            setupOps = UiAstJobSetupOperationsImpl.builder()
                    .owner(this)
                    .build();
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Scan PHP smoke project with medium level vulnerabilities")
    public void scanPhpSmoke() {
        Path sources = getPackedResourceFile("code/php-smoke-medium.7z");
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

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

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .failIfFailed(true)
                .failIfUnstable(false)
                .projectName(EXISTING_PHP_SMOKE_MEDIUM_PROJECT)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .reports(reports)
                .build();
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
    }
    @SneakyThrows
    @Test
    @DisplayName("Scan PHP smoke project with miscellaneous level vulnerabilities")
    public void scanPhpSmokeMisc() {
        Path sources = getPackedResourceFile("code/php-smoke-misc.7z");
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        Reports reports = new Reports();

        RawData rawData = new RawData();
        rawData.setFileName(UUID.randomUUID() + ".json");
        reports.getRaw().add(rawData);

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .failIfFailed(true)
                .failIfUnstable(false)
                .projectName(EXISTING_PHP_SMOKE_MISC_PROJECT)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .reports(reports)
                .build();
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
    }

    @SneakyThrows
    @Test
    @DisplayName("Test async scan duration")
    public void scanPhpSmokeAsync() {
        Path sources = getPackedResourceFile("code/php-smoke-medium.7z");
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .failIfFailed(true)
                .failIfUnstable(false)
                .projectName(EXISTING_PHP_SMOKE_MEDIUM_PROJECT)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .build();
        Instant start = Instant.now();
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
        Duration syncScan = Duration.between(start, Instant.now());

        astJob.setAsync(true);
        start = Instant.now();
        res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
        Duration asyncScan = Duration.between(start, Instant.now());
        Assertions.assertEquals(asyncScan.compareTo(syncScan), -1);
    }
}
