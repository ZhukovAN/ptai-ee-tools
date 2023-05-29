package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.contrastsecurity.sarif.SarifSchema210;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.SonarGiif;
import com.ptsecurity.misc.tools.TempFile;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.File;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.FAILED;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.SUCCESS;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.GENERIC_POLICY;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

@DisplayName("Check new JSON-defined project scans")
@Slf4j
class JsonAstIT extends BaseCliIT {
    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Execute AST of new project with no policy defined")
    public void scanNewProjectWithoutPolicy() {
        UnifiedAiProjScanSettings settings = PHP_SMOKE.getSettings().clone().setProjectName(randomProjectName());

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", PHP_SMOKE.getCode().toString(),
                "--settings-json", settings.serializeToFile().toString());
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Execute AST of new project ignoring policy assessment result")
    public void scanNewProjectAndIgnorePolicy() {
        UnifiedAiProjScanSettings settings = PHP_SMOKE.getSettings().clone().setProjectName(randomProjectName());
        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", PHP_SMOKE.getCode().toString(),
                "--settings-json", settings.serializeToFile().toString(),
                "--policy-json", GENERIC_POLICY.getPath().toString());
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Execute AST of new project with policy assessment")
    public void failNewProjectScanDueToPolicyAssessment() {
        UnifiedAiProjScanSettings settings = PHP_SMOKE.getSettings().clone().setProjectName(randomProjectName());
        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", PHP_SMOKE.getCode().toString(),
                "--settings-json", settings.serializeToFile().toString(),
                "--policy-json", GENERIC_POLICY.getPath().toString(),
                "--fail-if-failed");
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Execute AST of new project with missing dependencies")
    public void failNewProjectScanWithMissingDependencies() {
        UnifiedAiProjScanSettings settings = JAVA_APP01.getSettings().clone().setProjectName(randomProjectName());
        settings.setDownloadDependencies(false);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", JAVA_APP01.getCode().toString(),
                "--settings-json", settings.serializeToFile().toString(),
                "--fail-if-unstable");
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Execute AST of new project with explicit report generation")
    public void scanAndGenerateReports() {
        try (TempFile reportsFolder = TempFile.createFolder()) {
            UnifiedAiProjScanSettings settings = PHP_SMOKE.getSettings().clone().setProjectName(randomProjectName());

            int res = new CommandLine(new Plugin()).execute(
                    "json-ast",
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--input", PHP_SMOKE.getCode().toString(),
                    "--output", reportsFolder.toString(),
                    "--settings-json", settings.serializeToFile().toString(),
                    "--report-template", "Scan results report",
                    "--report-file", "results.en.html",
                    "--raw-data-file", "raw.json");
            Assertions.assertEquals(SUCCESS.getCode(), res);
            Assertions.assertTrue(reportsFolder.toPath().resolve("results.en.html").toFile().exists());
            Assertions.assertTrue(reportsFolder.toPath().resolve("raw.json").toFile().exists());
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Execute AST of new project with JSON-defined report generation")
    public void scanAndGenerateJsonDefinedReports() {
        try (TempFile reportsJson = TempFile.createFile();
             TempFile reportsFolder = TempFile.createFolder()) {
            UnifiedAiProjScanSettings settings = PHP_SMOKE.getSettings().clone().setProjectName(randomProjectName());

            FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

            int res = new CommandLine(new Plugin()).execute(
                    "json-ast",
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--input", PHP_SMOKE.getCode().toString(),
                    "--output", reportsFolder.toString(),
                    "--settings-json", settings.serializeToFile().toString(),
                    "--report-json", reportsJson.toString());
            Assertions.assertEquals(SUCCESS.getCode(), res);
            Assertions.assertTrue(reportsFolder.toPath().resolve("report.ru.html").toFile().exists());
            Assertions.assertTrue(reportsFolder.toPath().resolve("raw.json").toFile().exists());
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Execute AST of every tiny project")
    public void scanTinyProjects() {
        for (Project project : TINY) {
            UnifiedAiProjScanSettings settings = project.getSettings().clone().setProjectName(randomProjectName());
            int res = new CommandLine(new Plugin()).execute(
                    "json-ast",
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--input", project.getCode().toString(),
                    "--settings-json", settings.serializeToFile().toString());
            Assertions.assertEquals(SUCCESS.getCode(), res);
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Execute AST of new project with SARIF and GIIF report generation")
    public void scanAndGenerateGiifReports() {
        try (TempFile reportsFolder = TempFile.createFolder()) {
            UnifiedAiProjScanSettings settings = PHP_SMOKE.getSettings().clone().setProjectName(randomProjectName());

            int res = new CommandLine(new Plugin()).execute(
                    "json-ast",
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--input", PHP_SMOKE.getCode().toString(),
                    "--output", reportsFolder.toString(),
                    "--settings-json", settings.serializeToFile().toString(),
                    "--sarif-report-file", "sarif.json",
                    "--giif-report-file", "giif.json");
            Assertions.assertEquals(SUCCESS.getCode(), res);

            File sarifFile = reportsFolder.toPath().resolve("sarif.json").toFile();
            Assertions.assertTrue(sarifFile.exists());
            SarifSchema210 sarif = createObjectMapper().readValue(sarifFile, SarifSchema210.class);
            Assertions.assertEquals("Positive Technologies", sarif.getRuns().get(0).getTool().getDriver().getOrganization());

            File giifFile = reportsFolder.toPath().resolve("giif.json").toFile();
            Assertions.assertTrue(giifFile.exists());
            SonarGiif.SonarGiifReport giifReport = createObjectMapper().readValue(giifFile, SonarGiif.SonarGiifReport.class);
            Assertions.assertFalse(giifReport.getIssues().isEmpty());
        }
    }
}