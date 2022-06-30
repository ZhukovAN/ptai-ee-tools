package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.contrastsecurity.sarif.SarifSchema210;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.SonarGiif;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
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

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.RU;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Report.Format.HTML;

@DisplayName("Report generation tests")
@Tag("integration")
@Slf4j
class GenerateReportIT extends BaseCliIT {
    protected Path destination;

    @SneakyThrows
    @BeforeEach
    @Override
    public void pre() {
        super.pre();
        destination = Files.createTempDirectory(TEMP_FOLDER(), "ptai-");
    }

    @Test
    @DisplayName("Show usage of report generator")
    public void testShowUsage(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
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
        UUID scanResultId = getLatestCompleteScanResults(BaseAstIT.PHP_SMOKE_MEDIUM.getName());
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

        pair = new ImmutablePair<>("report-ru.html", new ArrayList<>());
        pair.getRight().addAll(Arrays.asList(
                "--report-file", pair.getLeft(),
                "--report-template", "Отчет по результатам сканирования",
                "--report-locale", RU.name(),
                "--report-format", HTML.name()));
        cases.add(pair);

        for (int i = 1 ; i < 3 ; i++) {
            Path folder = Paths.get(destination.toString()).resolve(UUID.randomUUID().toString());
            List<String> args = new ArrayList<>(Arrays.asList(
                    "generate-report",
                    "--url", CONNECTION().getUrl(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--token", CONNECTION().getToken(),
                    "--output", folder.toString(),
                    "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName()));
            if (null != scanResultId) {
                args.add("--scan-result-id");
                args.add(scanResultId.toString());
            }
            for (int j = 0 ; j < 2 ; j++)
                if (0 != (i & 1 << j))
                    args.addAll(cases.get(j).getRight());
            Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
            Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
            for (int j = 0 ; j < 2 ; j++)
                if (0 != (i & 1 << j))
                    Assertions.assertTrue(folder.resolve(cases.get(j).getLeft()).toFile().exists());
        }
    }

    @SneakyThrows
    public UUID getLatestCompleteScanResults(@NonNull final String project) {
        AbstractApiClient client = Factory.client(CONNECTION_SETTINGS());
        ProjectTasks tasks = new Factory().projectTasks(client);
        UUID projectId = tasks.searchProject(project);
        Assertions.assertNotNull(projectId);
        return tasks.getLatestCompleteAstResult(projectId);
    }

    @Test
    @DisplayName("Fail when duplicate file names are used")
    public void testDuplicateFileNamesProcessing(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", destination.toString(),
                "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--report-template", "Отчет OWASP Top 10 2017",
                "--report-file", "owasp.ru.html",
                "--report-locale", EN.name(),
                "--report-format", HTML.name(),
                "--raw-data-file", "raw.json");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Fail when missing template names are used")
    public void testMissingTemplateNamesProcessing(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", destination.toString(),
                "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--report-template", "Отчет OWASP Top 10 2017 ",
                "--report-file", "owasp.ru.html",
                "--report-locale", EN.name(),
                "--report-format", HTML.name());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate multiple JSON-defined reports for specific app01 scan results")
    public void testLatestJsonDefinedReportsGeneration(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path reportsJson = TEMP_FOLDER().resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", destination.toString(),
                "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--scan-result-id", getLatestCompleteScanResults(BaseAstIT.PHP_SMOKE_MEDIUM.getName()).toString(),
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        checkReports(reportsJson, destination);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail generate invalid JSON-defined reports for specific app01 scan results")
    public void testLatestInvalidJsonDefinedReportsGeneration(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path reportsJson = TEMP_FOLDER().resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.4.json"), reportsJson.toFile());

        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", destination.toString(),
                "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--scan-result-id", getLatestCompleteScanResults(BaseAstIT.PHP_SMOKE_MEDIUM.getName()).toString(),
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate JSON-defined reports for specific app01 scan results using extended filters")
    public void testLatestExtendedJsonDefinedReportsGeneration(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path reportsJson = TEMP_FOLDER().resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.5.json"), reportsJson.toFile());
        
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", destination.toString(),
                "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--scan-result-id", getLatestCompleteScanResults(BaseAstIT.PHP_SMOKE_MEDIUM.getName()).toString(),
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        checkReports(reportsJson, destination);
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate reports with- and without DFD and glossary")
    public void generateReportsWithAndWithoutDfdAndGlossary(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path reportMin = destination.resolve("minimal.html");
        Path reportMax = destination.resolve("maximum.html");
        Path reportDfd = destination.resolve("dfd.html");
        Path reportGlossary = destination.resolve("glossary.html");

        final String scanResultId = getLatestCompleteScanResults(BaseAstIT.PHP_SMOKE_MEDIUM.getName()).toString();

        for (Path report : new Path[] { reportMin, reportMax, reportDfd, reportGlossary }) {
            List<String> args = new ArrayList<>(Arrays.asList(
                    "generate-report",
                    "--url", CONNECTION().getUrl(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--token", CONNECTION().getToken(),
                    "--output", destination.toString(),
                    "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                    "--scan-result-id", scanResultId,
                    "--report-file", report.getFileName().toString(),
                    "--report-template", "Scan results report",
                    "--report-locale", EN.name(),
                    "--report-format", HTML.name()));
            if (report.equals(reportMax) || report.equals(reportDfd)) args.add("--report-include-dfd");
            if (report.equals(reportMax) || report.equals(reportGlossary)) args.add("--report-include-glossary");
            Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
            Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        }
        Assertions.assertTrue(reportMin.toFile().length() < reportDfd.toFile().length());
        Assertions.assertTrue(reportMin.toFile().length() < reportGlossary.toFile().length());
        Assertions.assertTrue(reportMin.toFile().length() < reportMax.toFile().length());

        Assertions.assertTrue(reportDfd.toFile().length() < reportMax.toFile().length());
        Assertions.assertTrue(reportGlossary.toFile().length() < reportMax.toFile().length());
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate SARIF report")
    public void generateSarifReport(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path report = destination.resolve("sarif.json");
        final String scanResultId = getLatestCompleteScanResults(BaseAstIT.PHP_SMOKE_MEDIUM.getName()).toString();

        List<String> args = new ArrayList<>(Arrays.asList(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", destination.toString(),
                "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--scan-result-id", scanResultId,
                "--sarif-report-file", report.getFileName().toString()));
        Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);

        ObjectMapper mapper = createFaultTolerantObjectMapper();
        SarifSchema210 sarif = mapper.readValue(report.toFile(), SarifSchema210.class);
        Assertions.assertEquals("Positive Technologies", sarif.getRuns().get(0).getTool().getDriver().getOrganization());
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate filtered JSON-defined SARIF report")
    public void generateFilteredSarifReport(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path reportFull = destination.resolve("sarif.full.json");
        Path reportLow = destination.resolve("sarif.low.json");
        Path reportMedium = destination.resolve("sarif.medium.json");
        final String scanResultId = getLatestCompleteScanResults(BaseAstIT.PHP_SMOKE_MEDIUM.getName()).toString();

        Path reportsJson = TEMP_FOLDER().resolve(UUID.randomUUID().toString());
        FileUtils.copyInputStreamToFile(getResourceStream("json/scan/reports/reports.6.json"), reportsJson.toFile());

        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", destination.toString(),
                "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--scan-result-id", scanResultId,
                "--report-json", reportsJson.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);

        Assertions.assertTrue(reportFull.toFile().length() > reportLow.toFile().length());
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        SarifSchema210 sarifFull = mapper.readValue(reportFull.toFile(), SarifSchema210.class);
        SarifSchema210 sarifLow = mapper.readValue(reportLow.toFile(), SarifSchema210.class);
        SarifSchema210 sarifMedium = mapper.readValue(reportMedium.toFile(), SarifSchema210.class);
        Assertions.assertEquals(sarifLow.getRuns().get(0).getResults().size(), 0);
        Assertions.assertNotEquals(sarifFull.getRuns().get(0).getResults().size(), 0);
        Assertions.assertNotEquals(sarifMedium.getRuns().get(0).getResults().size(), 0);
        Assertions.assertEquals(sarifFull.getRuns().get(0).getResults().size(), sarifMedium.getRuns().get(0).getResults().size());
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate GIIF report")
    public void generateGiifReport(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        Path report = destination.resolve("giif.json");
        final String scanResultId = getLatestCompleteScanResults(BaseAstIT.PHP_SMOKE_MEDIUM.getName()).toString();

        List<String> args = new ArrayList<>(Arrays.asList(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", destination.toString(),
                "--project-name", BaseAstIT.PHP_SMOKE_MEDIUM.getName(),
                "--scan-result-id", scanResultId,
                "--giif-report-file", report.getFileName().toString()));
        Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);

        ObjectMapper mapper = createFaultTolerantObjectMapper();
        SonarGiif.SonarGiifReport giifReport = mapper.readValue(report.toFile(), SonarGiif.SonarGiifReport.class);
        Assertions.assertFalse(giifReport.getIssues().isEmpty());
    }

    @SneakyThrows
    protected static void checkReports(@NonNull final Path reportsJson, @NonNull final Path destination) {
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        Reports reports = mapper.readValue(reportsJson.toFile(), Reports.class);
        reports.getReport().forEach((r) -> {
            File report = destination.resolve(r.getFileName()).toFile();
            Assertions.assertTrue(report.exists());
        });
        reports.getRaw().forEach((r) -> {
            File report = destination.resolve(r.getFileName()).toFile();
            Assertions.assertTrue(report.exists());
        });
    }

}