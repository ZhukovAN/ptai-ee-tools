package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.*;
import picocli.CommandLine;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

@DisplayName("Check JSON-defined AST scans")
@Tag("integration-legacy")
class JsonAstIT extends BaseCliAstIT {
    protected String newProjectName;

    protected AiProjScanSettings scanPhpSettings;
    protected Policy[] scanPolicy;

    @SneakyThrows
    protected String savedScanSettingsPath() {
        Assertions.assertNotNull(scanPhpSettings);
        File scanSettingsFile = Files.createTempFile(TEMP_FOLDER, "ptai-", "-settings").toFile();
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        mapper.writeValue(scanSettingsFile, scanPhpSettings);
        return scanSettingsFile.getAbsolutePath();
    }

    @SneakyThrows
    protected String savedScanPolicyPath() {
        Assertions.assertNotNull(scanPolicy);
        File scanPolicyFile = Files.createTempFile(TEMP_FOLDER, "ptai-", "-policy").toFile();
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        mapper.writeValue(scanPolicyFile, scanPolicy);
        return scanPolicyFile.getAbsolutePath();
    }
    
    @SneakyThrows
    @BeforeEach
    @Override
    public void pre() {
        super.pre();
        newProjectName = "junit-" + UUID.randomUUID();

        String jsonSettings = getResourceString("json/scan/settings/settings.minimal.aiproj");
        Assertions.assertFalse(StringUtils.isEmpty(jsonSettings));
        scanPhpSettings = JsonSettingsHelper.verify(jsonSettings);
        scanPhpSettings.setProgrammingLanguage(Language.PHP);

        String jsonPolicy = getResourceString("json/scan/settings/policy.generic.json");
        Assertions.assertFalse(StringUtils.isEmpty(jsonPolicy));
        scanPolicy = JsonPolicyHelper.verify(jsonPolicy);
    }

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
        scanPhpSettings.setProjectName(newProjectName);
        scanPhpSettings.setIsDownloadDependencies(false);

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--input", sourcesPhpMedium.toString(),
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