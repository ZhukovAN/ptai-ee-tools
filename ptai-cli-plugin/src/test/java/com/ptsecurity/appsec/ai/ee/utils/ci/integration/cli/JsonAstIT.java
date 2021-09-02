package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

@DisplayName("Check JSON-defined AST scans")
@Tag("integration")
class JsonAstIT extends BaseJsonIT {
    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with no policy defined")
    public void testMissingPolicy() {
        scanPhpSettings.setProjectName(newProjectName);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--settings-json", savedScanSettingsPath());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project ignoring policy assessment result")
    public void testIgnorePolicy() {
        scanPhpSettings.setProjectName(newProjectName);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--settings-json", savedScanSettingsPath(),
                "--policy-json", savedScanPolicyPath());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with policy assessment")
    public void testJsonAst() {
        scanPhpSettings.setProjectName(newProjectName);
        scanPhpSettings.setProgrammingLanguage(Language.PHP);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--input", sourcesPhpHigh.toString(),
                "--output", destination.toString(),
                "--settings-json", savedScanSettingsPath(),
                "--policy-json", savedScanPolicyPath(),
                "--fail-if-failed");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with missing dependencies")
    public void testJsonAstWithMissingDependencies() {
        AiProjScanSettings scanJavaSettings = scanPhpSettings;
        scanJavaSettings.setProjectName(newProjectName);
        scanJavaSettings.setIsDownloadDependencies(false);
        scanJavaSettings.setProgrammingLanguage(Language.JAVA);
        // As we changed programming language we need also to reset scan app type
        scanJavaSettings.setScanAppType(null);
        scanJavaSettings.fix();

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--input", sourcesJavaMisc.toString(),
                "--output", destination.toString(),
                "--settings-json", savedScanSettingsPath(),
                "--fail-if-unstable");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with explicit report generation")
    public void testExplicitReports() {
        scanPhpSettings.setProjectName(newProjectName);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--settings-json", savedScanSettingsPath(),
                "--report-template", "Отчет OWASP Top 10 2017",
                "--report-file", "owasp.ru.html",
                "--report-locale", Reports.Locale.RU.name(),
                "--report-format", Reports.Report.Format.HTML.name(),
                "--data-file", "owasp.en.json",
                "--data-locale", Reports.Locale.EN.name(),
                "--data-format", Reports.Data.Format.JSON.name(),
                "--raw-data-file", "raw.json");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("owasp.ru.html").toFile().exists());
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("owasp.en.json").toFile().exists());
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("raw.json").toFile().exists());
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with JSON-defined report generation")
    public void testJsonDefinedReports() {
        scanPhpSettings.setProjectName(newProjectName);

        Path reportsJson = TEMP_FOLDER.resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--input", sourcesPhpMedium.toString(),
                "--output", destination.toString(),
                "--settings-json", savedScanSettingsPath(),
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("report.ru.xml").toFile().exists());
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("data.en.json").toFile().exists());
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("data.en.xml").toFile().exists());
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("raw.json").toFile().exists());
    }
}