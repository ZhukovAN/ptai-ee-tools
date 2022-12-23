package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.Report;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.UiAstJobSetupOperationsImpl;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project.PHP_SMOKE;

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
    @Tag("scan")
    @DisplayName("Scan PHP smoke project with medium level vulnerabilities")
    public void scanPhpSmoke() {
        try (TempFile destination = TempFile.createFolder()) {
            setup(PHP_SMOKE);

            GenericAstJob astJob = UiAstJobImpl.builder()
                    .async(false)
                    .fullScanMode(true)
                    .projectName(PHP_SMOKE.getName())
                    .connectionSettings(CONNECTION_SETTINGS())
                    .console(System.out)
                    .sources(PHP_SMOKE.getCode())
                    .destination(destination.toPath())
                    .build();

            Report.builder().owner(astJob).report(report).build().attach(astJob);
            RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);
            FailIfAstFailed.builder().build().attach(astJob);

            AbstractJob.JobExecutionResult res = astJob.execute();
            Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @DisplayName("Fail scan because of missing report template")
    public void failMissingReportTemplate() {
        try (TempFile destination = TempFile.createFolder()) {
            setup(PHP_SMOKE);

            GenericAstJob astJob = UiAstJobImpl.builder()
                    .async(false)
                    .fullScanMode(true)
                    .projectName(PHP_SMOKE.getName())
                    .connectionSettings(CONNECTION_SETTINGS())
                    .console(System.out)
                    .sources(PHP_SMOKE.getCode())
                    .destination(destination.toPath())
                    .build();

            report.setTemplate(report.getTemplate() + "-" + UUID.randomUUID());
            Report.builder().owner(astJob).report(report).build().attach(astJob);
            FailIfAstFailed.builder().build().attach(astJob);

            AbstractJob.JobExecutionResult res = astJob.execute();
            Assertions.assertEquals(res, AbstractJob.JobExecutionResult.FAILED);
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @DisplayName("Scan PHP smoke project with miscellaneous level vulnerabilities")
    public void scanPhpSmokeMisc() {
        try (TempFile destination = TempFile.createFolder()) {
            setup(PHP_SMOKE);

            GenericAstJob astJob = UiAstJobImpl.builder()
                    .async(false)
                    .fullScanMode(true)
                    .projectName(PHP_SMOKE.getName())
                    .connectionSettings(CONNECTION_SETTINGS())
                    .console(System.out)
                    .sources(PHP_SMOKE.getCode())
                    .destination(destination.toPath())
                    .build();

            FailIfAstFailed.builder().build().attach(astJob);

            AbstractJob.JobExecutionResult res = astJob.execute();
            Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @DisplayName("Test async scan duration")
    public void scanPhpSmokeAsync() {
        try (TempFile destination = TempFile.createFolder()) {
            Project phpSmokeClone = PHP_SMOKE.randomClone();
            setup(phpSmokeClone);
            GenericAstJob astJob = UiAstJobImpl.builder()
                    .async(false)
                    .fullScanMode(true)
                    .projectName(phpSmokeClone.getName())
                    .connectionSettings(CONNECTION_SETTINGS())
                    .console(System.out)
                    .sources(phpSmokeClone.getCode())
                    .destination(destination.toPath())
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
}
