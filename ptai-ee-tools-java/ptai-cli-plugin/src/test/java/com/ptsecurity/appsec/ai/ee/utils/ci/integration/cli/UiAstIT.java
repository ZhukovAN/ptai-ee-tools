package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Report.Format.HTML;

@DisplayName("Check UI-defined AST scans")
class UiAstIT extends BaseIT {
    @Test
    @DisplayName("Show usage of UI-defined AST")
    void testUiAstShowUsage() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast");
        Assertions.assertEquals(BaseCommand.ExitCode.INVALID_INPUT.getCode(), res);
    }

    @Test
    @DisplayName("AST of existing project")
    void testExistingProject() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--truststore", PEM_PATH,
                "--url", PTAI_URL,
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("AST of existing project with no source code included")
    void testNoSourcesIncluded() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--truststore", PEM_PATH,
                "--url", PTAI_URL,
                "--token", TOKEN,
                "--includes", "**/*.java",
                "--excludes", "**/*");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("AST of policy violating project")
    void testPolicyFailForExistingProject() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--truststore", PEM_PATH,
                "--url", PTAI_URL,
                "--token", TOKEN,
                "--fail-if-failed");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("AST of missing project with custom truststore")
    void testMissingProject() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT + UUID.randomUUID().toString(),
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--truststore", PEM_PATH,
                "--url", PTAI_URL,
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("AST of existing project without custom truststore")
    void testWithoutTruststore() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--url", PTAI_URL,
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Insecure AST of existing project without custom truststore")
    void testInsecureWithoutTruststore() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--url", PTAI_URL,
                "--token", TOKEN,
                "--insecure");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Twice AST of existing project to test report overwrite")
    void testReportRewrite() {
        Path report = Paths.get(REPORT_FOLDER).resolve("owasp.en.html");
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--report-file", report.getFileName().toString(),
                "--report-template", "OWASP top 10 2017 report",
                "--report-format", HTML.name(),
                "--report-locale", Reports.Locale.EN.name());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(report.toFile().exists());
        BasicFileAttributes attr = Files.readAttributes(report, BasicFileAttributes.class);
        FileTime fileTime = attr.creationTime();

        res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--report-file", report.getFileName().toString(),
                "--report-template", "OWASP top 10 2017 report",
                "--report-format", HTML.name(),
                "--report-locale", Reports.Locale.EN.name());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(report.toFile().exists());
        attr = Files.readAttributes(report, BasicFileAttributes.class);
        Assertions.assertNotEquals(fileTime, attr.lastModifiedTime());
    }

    @Test
    @DisplayName("AST existing project with multiple JSON-defined reports")
    void testJsonDefinedReports() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--report-json", getResourcePath("json/reports.1.json"));
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("report.ru.xml").toFile().exists());
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("data.en.json").toFile().exists());
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("data.en.xml").toFile().exists());
        Assertions.assertTrue(Paths.get(REPORT_FOLDER).resolve("raw.json").toFile().exists());
    }

    @Test
    @DisplayName("AST existing project with bad JSON-defined reports")
    public void testInvalidJsonDefinedReports() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--report-json", getResourcePath("json/reports.2.json"));
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("AST existing project with JSON-defined reports with missing templates")
    public void testMissingJsonDefinedReports() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--report-json", getResourcePath("json/reports.3.json"));
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Asynchronous AST of existing project")
    void testExistingProjectAsync() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--truststore", PEM_PATH,
                "--url", PTAI_URL,
                "--token", TOKEN,
                "--async");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Asynchronous AST of missing project with custom truststore")
    void testMissingProjectAsync() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT + UUID.randomUUID().toString(),
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--truststore", PEM_PATH,
                "--url", PTAI_URL,
                "--token", TOKEN,
                "--async");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Asynchronous AST of existing project without custom truststore")
    void testWithoutTruststoreAsync() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT,
                "--input", SOURCES_FOLDER,
                "--output", REPORT_FOLDER,
                "--url", PTAI_URL,
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }
}