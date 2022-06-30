package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsTestHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.*;
import picocli.CommandLine;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings.ScanAppType.JAVA;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.*;

@DisplayName("Check JSON-defined AST scans")
@Tag("integration")
@Slf4j
class JsonAstIT extends BaseJsonIT {
    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with no policy defined")
    public void testMissingPolicy(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE_MEDIUM.getSettings());

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", PHP_SMOKE_MEDIUM.getCode().toString(),
                "--output", destination.toString(),
                "--settings-json", settings.serializeToFile().toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project ignoring policy assessment result")
    public void testIgnorePolicy(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE_MEDIUM.getSettings());

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", PHP_SMOKE_MEDIUM.getCode().toString(),
                "--output", destination.toString(),
                "--settings-json", settings.serializeToFile().toString(),
                "--policy-json", GENERIC_POLICY.getPath().toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with policy assessment")
    public void testJsonAst(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE_HIGH.getSettings());
        settings.setProjectName(PHP_SMOKE_HIGH.getName());
        settings.setProgrammingLanguage(Language.PHP);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", PHP_SMOKE_HIGH.getCode().toString(),
                "--output", destination.toString(),
                "--settings-json", settings.serializeToFile().toString(),
                "--policy-json", GENERIC_POLICY.getPath().toString(),
                "--fail-if-failed");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with missing dependencies")
    public void testJsonAstWithMissingDependencies(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(JAVA_APP01.getSettings());
        settings.setIsDownloadDependencies(false);
        settings.setScanAppType(JAVA);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", JAVA_APP01.getCode().toString(),
                "--output", destination.toString(),
                "--settings-json", settings.serializeToFile().toString(),
                "--fail-if-unstable");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with explicit report generation")
    public void testExplicitReports(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE_MEDIUM.getSettings());

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", PHP_SMOKE_MEDIUM.getCode().toString(),
                "--output", destination.toString(),
                "--settings-json", settings.serializeToFile().toString(),
                "--report-template", "Отчет OWASP Top 10 2017",
                "--report-file", "owasp.ru.html",
                "--report-locale", Reports.Locale.RU.name(),
                "--report-format", Reports.Report.Format.HTML.name(),
                "--raw-data-file", "raw.json");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("owasp.ru.html").toFile().exists());
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("raw.json").toFile().exists());
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute AST of new project with JSON-defined report generation")
    public void testJsonDefinedReports(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE_MEDIUM.getSettings());

        Path reportsJson = TEMP_FOLDER().resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--input", PHP_SMOKE_MEDIUM.getCode().toString(),
                "--output", destination.toString(),
                "--settings-json", settings.serializeToFile().toString(),
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("report.ru.html").toFile().exists());
        Assertions.assertTrue(Paths.get(destination.toString()).resolve("raw.json").toFile().exists());
    }
}