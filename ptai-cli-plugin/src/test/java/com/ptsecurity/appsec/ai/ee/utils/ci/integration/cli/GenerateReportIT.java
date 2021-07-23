package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.*;
import picocli.CommandLine;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Data.Format.JSON;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Data.Format.XML;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.RU;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report.Format.HTML;

@DisplayName("Report generation tests")
@Tag("integration-legacy")
class GenerateReportIT extends BaseCliIT {
    protected Path destination;

    @SneakyThrows
    @BeforeEach
    @Override
    public void pre() {
        super.pre();
        destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");
    }

    @Test
    @DisplayName("Show usage of report generator")
    public void testShowUsage() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report");
        Assertions.assertEquals(BaseCommand.ExitCode.INVALID_INPUT.getCode(), res);
    }

    @Test
    @DisplayName("Generate latest app01 scan results report using all possible configurations")
    public void testLatestScanResultsReport() {
        testScanResultsReport(null);
    }

    @Test
    @DisplayName("Generate specific app01 scan results report using all possible configurations")
    public void testSpecificScanResultsReport() {
        UUID scanResultId = getLatestCompleteScanResults(EXISTING_PHP_SMOKE_MEDIUM_PROJECT);
        testScanResultsReport(scanResultId);
    }

    /**
     * Method calls CLI for generating all possible non-JSON-defined reporting combinations
     * @param scanResultId Scan for report to be generated. If null then latest scan result will be used
     */
    public void testScanResultsReport(final UUID scanResultId) {
        // Generate all possible non-JSON-defined reporting combinations
        List<Pair<String, List<String>>> cases = new ArrayList<>();
        Pair<String, List<String>> pair = new ImmutablePair<>("raw.json", new ArrayList<>());
        pair.getRight().addAll(Arrays.asList("--raw-data-file", pair.getLeft()));
        cases.add(pair);

        pair = new ImmutablePair<>("data-en.xml", new ArrayList<>());
        pair.getRight().addAll(Arrays.asList(
                "--data-file", pair.getLeft(),
                "--data-locale", EN.name(),
                "--data-format", XML.name()));
        cases.add(pair);

        pair = new ImmutablePair<>("report-ru.html", new ArrayList<>());
        pair.getRight().addAll(Arrays.asList(
                "--report-file", pair.getLeft(),
                "--report-template", "Отчет по результатам сканирования",
                "--report-locale", RU.name(),
                "--report-format", HTML.name()));
        cases.add(pair);

        for (int i = 1 ; i < 7 ; i++) {
            Path folder = Paths.get(destination.toString()).resolve(UUID.randomUUID().toString());
            List<String> args = new ArrayList<>(Arrays.asList(
                    "generate-report",
                    "--url", URL,
                    "--truststore", PEM.toString(),
                    "--token", TOKEN,
                    "--output", folder.toString(),
                    "--project-name", EXISTING_PHP_SMOKE_MEDIUM_PROJECT));
            if (null != scanResultId) {
                args.add("--scan-result-id");
                args.add(scanResultId.toString());
            }
            for (int j = 0 ; j < 3 ; j++)
                if (0 != (i & 1 << j))
                    args.addAll(cases.get(j).getRight());
            Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
            Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
            for (int j = 0 ; j < 3 ; j++)
                if (0 != (i & 1 << j))
                    Assertions.assertTrue(folder.resolve(cases.get(j).getLeft()).toFile().exists());
        }
    }

    @SneakyThrows
    public UUID getLatestCompleteScanResults(@NonNull final String project) {
        AbstractApiClient client = Factory.client(ConnectionSettings.builder()
                .url(URL)
                .token(TOKEN)
                .insecure(true)
                .build());
        ProjectTasks tasks = new Factory().projectTasks(client);
        UUID projectId = tasks.searchProject(project);
        Assertions.assertNotNull(projectId);
        return tasks.getLatestCompleteAstResult(projectId);
    }

    @Test
    @DisplayName("Fail when duplicate file names are used")
    public void testDuplicateFileNamesProcessing() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--output", destination.toString(),
                "--project-name", EXISTING_PHP_SMOKE_MEDIUM_PROJECT,
                "--report-template", "Отчет OWASP Top 10 2017",
                "--report-file", "owasp.ru.html",
                "--report-locale", EN.name(),
                "--report-format", HTML.name(),
                "--data-file", "owasp.ru.html",
                "--data-locale", EN.name(),
                "--data-format", JSON.name(),
                "--raw-data-file", "raw.json");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Fail when missing template names are used")
    public void testMissingTemplateNamesProcessing() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--output", destination.toString(),
                "--project-name", EXISTING_PHP_SMOKE_MEDIUM_PROJECT,
                "--report-template", "Отчет OWASP Top 10 2017 ",
                "--report-file", "owasp.ru.html",
                "--report-locale", EN.name(),
                "--report-format", HTML.name());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate multiple JSON-defined reports for specific app01 scan results")
    public void testLatestJsonDefinedReportsGeneration() {
        Path reportsJson = TEMP_FOLDER.resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--output", destination.toString(),
                "--project-name", EXISTING_PHP_SMOKE_MEDIUM_PROJECT,
                "--scan-result-id", getLatestCompleteScanResults(EXISTING_PHP_SMOKE_MEDIUM_PROJECT).toString(),
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        checkReports(reportsJson, destination);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail generate invalid JSON-defined reports for specific app01 scan results")
    public void testLatestInvalidJsonDefinedReportsGeneration() {
        Path reportsJson = TEMP_FOLDER.resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.4.json"), reportsJson.toFile());

        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--output", destination.toString(),
                "--project-name", EXISTING_PHP_SMOKE_MEDIUM_PROJECT,
                "--scan-result-id", getLatestCompleteScanResults(EXISTING_PHP_SMOKE_MEDIUM_PROJECT).toString(),
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate JSON-defined reports for specific app01 scan results using extended filters")
    public void testLatestExtendedJsonDefinedReportsGeneration() {
        Path reportsJson = TEMP_FOLDER.resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.5.json"), reportsJson.toFile());
        
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--output", destination.toString(),
                "--project-name", EXISTING_PHP_SMOKE_MEDIUM_PROJECT,
                "--scan-result-id", getLatestCompleteScanResults(EXISTING_PHP_SMOKE_MEDIUM_PROJECT).toString(),
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        checkReports(reportsJson, destination);
    }

    @SneakyThrows
    protected static void checkReports(@NonNull final Path reportsJson, @NonNull final Path destination) {
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        Reports reports = mapper.readValue(reportsJson.toFile(), Reports.class);
        Stream.concat(reports.getReport().stream(), reports.getData().stream()).forEach((r) -> {
            File report = destination.resolve(r.getFileName()).toFile();
            Assertions.assertTrue(report.exists());
        });
        reports.getRaw().forEach((r) -> {
            File report = destination.resolve(r.getFileName()).toFile();
            Assertions.assertTrue(report.exists());
        });
    }

}