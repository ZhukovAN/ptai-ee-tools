package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsTestHelper;
import com.ptsecurity.misc.tools.TempFile;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.FAILED;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.SUCCESS;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.GENERIC_POLICY;
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
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE).randomizeProjectName();
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
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE).randomizeProjectName();
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
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE).randomizeProjectName();
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
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(JAVA_APP01).randomizeProjectName();
        settings.setIsDownloadDependencies(false);

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
            JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE).randomizeProjectName();

            int res = new CommandLine(new Plugin()).execute(
                    "json-ast",
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--input", PHP_SMOKE.getCode().toString(),
                    "--output", reportsFolder.toString(),
                    "--settings-json", settings.serializeToFile().toString(),
                    "--report-template", "Отчет OWASP Top 10 2017",
                    "--report-file", "owasp.ru.html",
                    "--raw-data-file", "raw.json");
            Assertions.assertEquals(SUCCESS.getCode(), res);
            Assertions.assertTrue(reportsFolder.toPath().resolve("owasp.ru.html").toFile().exists());
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
            JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE).randomizeProjectName();

            FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

            int res = new CommandLine(new Plugin()).execute(
                    "json-ast",
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--input", PHP_SMOKE.getCode().toString(),
                    "--output", reportsFolder.toString(),
                    "--settings-json", settings.toPath().toString(),
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
            JsonSettingsTestHelper settings = new JsonSettingsTestHelper(project).randomizeProjectName();
            int res = new CommandLine(new Plugin()).execute(
                    "json-ast",
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--input", project.getCode().toString(),
                    "--settings-json", settings.toPath().toString());
            Assertions.assertEquals(SUCCESS.getCode(), res);
        }
    }
}