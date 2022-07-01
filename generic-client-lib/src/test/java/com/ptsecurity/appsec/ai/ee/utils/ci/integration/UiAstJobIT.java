package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Report;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.UiAstJobSetupOperationsImpl;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@DisplayName("Test UI-based AST")
@Tag("integration")
@Slf4j
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
    public void scanPhpSmoke(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path destination = Files.createTempDirectory(TEMP_FOLDER(), "ptai-");

        PHP_SMOKE_MEDIUM.setup();

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .projectName(PHP_SMOKE_MEDIUM.getName())
                .connectionSettings(CONNECTION_SETTINGS())
                .console(System.out)
                .sources(PHP_SMOKE_MEDIUM.getCode())
                .destination(destination)
                .build();

        Report.builder().owner(astJob).report(report).build().attach(astJob);
        RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);
        FailIfAstFailed.builder().build().attach(astJob);

        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail scan because of missing report template")
    public void failMissingReportTemplate(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path destination = Files.createTempDirectory(TEMP_FOLDER(), "ptai-");

        PHP_SMOKE_MEDIUM.setup();

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .projectName(PHP_SMOKE_MEDIUM.getName())
                .connectionSettings(CONNECTION_SETTINGS())
                .console(System.out)
                .sources(PHP_SMOKE_MEDIUM.getCode())
                .destination(destination)
                .build();

        report.setTemplate(report.getTemplate() + "-" + UUID.randomUUID());
        Report.builder().owner(astJob).report(report).build().attach(astJob);
        FailIfAstFailed.builder().build().attach(astJob);

        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.FAILED);
    }

    @SneakyThrows
    @Test
    @DisplayName("Scan PHP smoke project with miscellaneous level vulnerabilities")
    public void scanPhpSmokeMisc(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path destination = Files.createTempDirectory(TEMP_FOLDER(), "ptai-");

        PHP_SMOKE_MISC.setup();

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .projectName(PHP_SMOKE_MISC.getName())
                .connectionSettings(CONNECTION_SETTINGS())
                .console(System.out)
                .sources(PHP_SMOKE_MISC.getCode())
                .destination(destination)
                .build();

        FailIfAstFailed.builder().build().attach(astJob);

        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
    }

    @SneakyThrows
    @Test
    @DisplayName("Test async scan duration")
    public void scanPhpSmokeAsync(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path destination = Files.createTempDirectory(TEMP_FOLDER(), "ptai-");

        PHP_SMOKE_MEDIUM.setup();

        GenericAstJob astJob = UiAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .projectName(PHP_SMOKE_MEDIUM.getName())
                .connectionSettings(CONNECTION_SETTINGS())
                .console(System.out)
                .sources(PHP_SMOKE_MEDIUM.getCode())
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
