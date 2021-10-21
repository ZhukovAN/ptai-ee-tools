package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.HtmlPdf;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.JsonXml;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
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

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .projectName(EXISTING_PHP_SMOKE_MEDIUM_PROJECT)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .build();

        HtmlPdf.builder().owner(astJob).report(report).build().attach(astJob);
        JsonXml.builder().owner(astJob).data(data).build().attach(astJob);
        RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);
        FailIfAstFailed.builder().build().attach(astJob);

        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail scan because of missing report template")
    public void failMissingReportTemplate() {
        Path sources = getPackedResourceFile("code/php-smoke-medium.7z");
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .projectName(EXISTING_PHP_SMOKE_MEDIUM_PROJECT)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .build();

        report.setTemplate(report.getTemplate() + "-" + UUID.randomUUID());
        HtmlPdf.builder().owner(astJob).report(report).build().attach(astJob);
        FailIfAstFailed.builder().build().attach(astJob);

        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.FAILED);
    }

    @SneakyThrows
    @Test
    @DisplayName("Scan PHP smoke project with miscellaneous level vulnerabilities")
    public void scanPhpSmokeMisc() {
        Path sources = getPackedResourceFile("code/php-smoke-misc.7z");
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .projectName(EXISTING_PHP_SMOKE_MISC_PROJECT)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .build();

        FailIfAstFailed.builder().build().attach(astJob);

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
