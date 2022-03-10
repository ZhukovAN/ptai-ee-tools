package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report.Format.HTML;

@DisplayName("Check UI-defined AST scans")
@Tag("integration")
class UiAstIT extends BaseCliAstIT {
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
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--truststore", PEM.toString(),
                "--url", URL,
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Fail AST of existing project with no source code included")
    void testNoSourcesIncluded() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--truststore", PEM.toString(),
                "--url", URL,
                "--token", TOKEN,
                "--includes", "**/*.java",
                "--excludes", "**/*");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Fail AST of policy violating project")
    void testPolicyFailForExistingProject() {
        BaseAstIT.setupProject(BaseAstIT.PHP_SMOKE_HIGH, BaseAstIT.getDefaultPolicy());
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_HIGH.getName(),
                "--input", sourcesPhpHigh.toString(),
                "--output", destination.toString(),
                "--truststore", PEM.toString(),
                "--url", URL,
                "--token", TOKEN,
                "--fail-if-failed");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Fail AST of missing project with custom truststore")
    void testMissingProject() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName() + UUID.randomUUID(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--truststore", PEM.toString(),
                "--url", URL,
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Fail AST of existing project without custom truststore")
    void testWithoutTruststore() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--url", URL,
                "--token", TOKEN,
                "--truststore", DUMMY.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Insecure AST of existing project without custom truststore")
    void testInsecureWithoutTruststore() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--url", URL,
                "--token", TOKEN,
                "--insecure");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Twice AST of existing project to test report overwrite")
    void testReportRewrite() {
        Path report = Paths.get(destination.toString()).resolve("owasp.en.html");
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--url", URL,
                "--truststore", PEM.toString(),
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
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--url", URL,
                "--truststore", PEM.toString(),
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

    @SneakyThrows
    @Test
    @DisplayName("AST existing project with multiple JSON-defined reports")
    void testJsonDefinedReports() {
        Path reportsJson = TEMP_FOLDER.resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        GenerateReportIT.checkReports(reportsJson, destination);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail AST existing project with bad JSON-defined reports")
    public void testInvalidJsonDefinedReports() {
        Path reportsJson = TEMP_FOLDER.resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.2.json"), reportsJson.toFile());

        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail AST existing project with JSON-defined reports with missing templates")
    public void testMissingJsonDefinedReports() {
        Path reportsJson = TEMP_FOLDER.resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.3.json"), reportsJson.toFile());

        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Asynchronous AST of existing project")
    void testExistingProjectAsync() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--truststore", PEM.toString(),
                "--url", URL,
                "--token", TOKEN,
                "--async");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Asynchronous AST of missing project with custom truststore")
    void testMissingProjectAsync() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName() + UUID.randomUUID(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--truststore", PEM.toString(),
                "--url", URL,
                "--token", TOKEN,
                "--async");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Asynchronous AST of existing project without custom truststore")
    void testWithoutTruststoreAsync() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--url", URL,
                "--token", TOKEN,
                "--truststore", DUMMY.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }
}