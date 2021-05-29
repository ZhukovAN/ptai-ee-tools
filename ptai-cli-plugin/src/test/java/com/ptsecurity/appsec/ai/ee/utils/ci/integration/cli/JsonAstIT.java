package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.nio.file.Paths;

@DisplayName("Check JSON-defined AST scans")
@Tag("integration-legacy")
class JsonAstIT extends BaseIT {

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with no policy defined")
    public void testMissingPolicy() {
        SCAN_SETTINGS.setProjectName(NEW_PROJECT);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--settings-json", saveScanSettings());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project ignoring policy assessment result")
    public void testIgnorePolicy() {
        SCAN_SETTINGS.setProjectName(NEW_PROJECT);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--settings-json", saveScanSettings(),
                "--policy-json", POLICY_PATH);
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with policy assessment")
    public void testJsonAst() {
        SCAN_SETTINGS.setProjectName(NEW_PROJECT);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--settings-json", saveScanSettings(),
                "--policy-json", POLICY_PATH,
                "--fail-if-failed");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with missing dependencies")
    public void testJsonAstWithMissingDependencies() {
        SCAN_SETTINGS.setProjectName(NEW_PROJECT);
        SCAN_SETTINGS.setDownloadDependencies(false);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--settings-json", saveScanSettings(),
                "--fail-if-unstable");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with explicit report generation")
    public void testExplicitReports() {
        SCAN_SETTINGS.setProjectName(NEW_PROJECT);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--settings-json", saveScanSettings(),
                "--report-template", "Отчет OWASP Top 10 2017",
                "--report-file", "owasp.ru.html",
                "--report-locale", Reports.Locale.RU.name(),
                "--report-format", Reports.Report.Format.HTML.name(),
                "--data-file", "owasp.en.json",
                "--data-locale", Reports.Locale.EN.name(),
                "--data-format", Reports.Data.Format.JSON.name(),
                "--raw-data-file", "raw.json");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("owasp.ru.html").toFile().exists());
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("owasp.en.json").toFile().exists());
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("raw.json").toFile().exists());
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with JSON-defined report generation")
    public void testJsonDefinedReports() {
        SCAN_SETTINGS.setProjectName(NEW_PROJECT);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--settings-json", saveScanSettings(),
                "--report-json", getResourcePath("json/reports.1.json"));
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("report.ru.xml").toFile().exists());
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("data.en.json").toFile().exists());
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("data.en.xml").toFile().exists());
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("raw.json").toFile().exists());
    }
}