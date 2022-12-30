package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.contrastsecurity.sarif.SarifSchema210;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.SonarGiif;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsTestHelper;
import com.ptsecurity.misc.tools.TempFile;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.*;
import picocli.CommandLine;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project.PHP_SMOKE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.*;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;
import static org.apache.commons.io.FileUtils.copyInputStreamToFile;

@DisplayName("Report generation tests")
@Tag("integration")
@Slf4j
class GenerateReportIT extends BaseCliIT {
    protected static UUID LATEST_COMPLETE_SCAN_RESULT_ID;

    @BeforeAll
    public static void init() {
        BaseCliIT.init();
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE);
        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--insecure",
                "--input", PHP_SMOKE.getCode().toString(),
                "--settings-json", settings.toPath().toString());
        Assertions.assertEquals(SUCCESS.getCode(), res);
        LATEST_COMPLETE_SCAN_RESULT_ID = getLatestCompleteScanResults(PHP_SMOKE.getName());
    }

    @Test
    @DisplayName("Show usage of report generator")
    public void showUsage() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report");
        Assertions.assertEquals(INVALID_INPUT.getCode(), res);
    }

    @Test
    @DisplayName("Generate latest PHP smoke scan results report using all possible combinations")
    public void generateAllScanReportsForLatestResult() {
        generateAllScanReports(null);
    }

    @Test
    @DisplayName("Generate specific PHP smoke scan results report using all possible combinations")
    public void generateAllScanReportsForSpecificResult() {
        generateAllScanReports(LATEST_COMPLETE_SCAN_RESULT_ID);
    }

    /**
     * Method calls CLI multiple times to generate reports using every possible
     * non-JSON-defined (i.e. using CLI parameters only) reporting combinations
     * @param scanResultId Scan for report to be generated. If null then latest scan result will be used
     */
    public void generateAllScanReports(final UUID scanResultId) {
        log.trace("Create list that will hold report file names / CLI parameters pairs");
        List<Pair<String, List<String>>> cases = new ArrayList<>();
        log.trace("Add raw json generation parameters");
        Pair<String, List<String>> pair = new ImmutablePair<>("raw.json", new ArrayList<>());
        pair.getRight().addAll(Arrays.asList("--raw-data-file", pair.getLeft()));
        cases.add(pair);
        log.trace("Add generic report generation parameters");
        pair = new ImmutablePair<>("report-ru.html", new ArrayList<>());
        pair.getRight().addAll(Arrays.asList(
                "--report-file", pair.getLeft(),
                "--report-template", "Отчет по результатам сканирования"));
        cases.add(pair);
        log.trace("Add SonarQube GIIF report generation parameters");
        pair = new ImmutablePair<>("giif.json", new ArrayList<>());
        pair.getRight().addAll(Arrays.asList("--giif-report-file", pair.getLeft()));
        cases.add(pair);
        log.trace("Add SARIF report generation parameters");
        pair = new ImmutablePair<>("sarif.json", new ArrayList<>());
        pair.getRight().addAll(Arrays.asList("--sarif-report-file", pair.getLeft()));
        cases.add(pair);

        log.trace("Four report types produce 2 ^ 4 = 16 CLI call combinations. Also skip very first as it doesn't contain reports");
        for (int i = 1 ; i < 16 ; i++) {
            try (TempFile reportsFolder = TempFile.createFolder()) {
                List<String> args = new ArrayList<>(Arrays.asList(
                        "generate-report",
                        "--url", CONNECTION().getUrl(),
                        "--token", CONNECTION().getToken(),
                        "--insecure",
                        "--output", reportsFolder.toString(),
                        "--project-name", PHP_SMOKE.getName()));
                if (null != scanResultId) {
                    args.add("--scan-result-id");
                    args.add(scanResultId.toString());
                }
                for (int j = 0; j < 4; j++)
                    if (0 != (i & 1 << j))
                        args.addAll(cases.get(j).getRight());
                log.trace("Execute CLI with parameters: {}", String.join(" ", args));
                Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
                Assertions.assertEquals(SUCCESS.getCode(), res);
                log.trace("Check reports");
                for (int j = 0; j < 4; j++)
                    if (0 != (i & 1 << j))
                        Assertions.assertTrue(reportsFolder.toPath().resolve(cases.get(j).getLeft()).toFile().exists());
            }
        }
    }

    @SneakyThrows
    private static UUID getLatestCompleteScanResults(@NonNull final String project) {
        UUID projectId = projectTasks.searchProject(project);
        Assertions.assertNotNull(projectId);
        return projectTasks.getLatestCompleteAstResult(projectId);
    }

    @Test
    @DisplayName("Fail when duplicate file names are used")
    public void failDuplicateReportFileNames() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", TempFile.createFile().toString(),
                "--project-name", PHP_SMOKE.getName(),
                "--report-template", "Scan results report",
                "--report-file", "owasp.en.html",
                "--raw-data-file", "owasp.en.html");
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Fail when missing template names are used")
    public void failMissingTemplate() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--output", TempFile.createFile().toString(),
                "--project-name", PHP_SMOKE.getName(),
                "--report-template", "Scan results report ",
                "--report-file", "owasp.en.html");
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate multiple JSON-defined reports for specific PHP smoke scan results")
    public void generateJsonDefinedReportsForSpecificScan() {
        try (TempFile reportsFolder = TempFile.createFolder();
             TempFile reportsJson = TempFile.createFile()) {
            copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

            Integer res = new CommandLine(new Plugin()).execute(
                    "generate-report",
                    "--url", CONNECTION().getUrl(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--token", CONNECTION().getToken(),
                    "--output", reportsFolder.toString(),
                    "--project-name", PHP_SMOKE.getName(),
                    "--scan-result-id", LATEST_COMPLETE_SCAN_RESULT_ID.toString(),
                    "--report-json", reportsJson.toString());
            Assertions.assertEquals(SUCCESS.getCode(), res);
            checkReports(reportsJson.toPath(), reportsFolder.toPath());
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail generate invalid JSON-defined reports for specific scan results")
    public void failInvalidReportsJson() {
        try (TempFile reportsJson = TempFile.createFile()) {
            copyInputStreamToFile(getResourceStream("json/scan/reports/reports.4.json"), reportsJson.toFile());
            Integer res = new CommandLine(new Plugin()).execute(
                    "generate-report",
                    "--url", CONNECTION().getUrl(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--token", CONNECTION().getToken(),
                    "--output", TempFile.createFile().toString(),
                    "--project-name", PHP_SMOKE.getName(),
                    "--scan-result-id", LATEST_COMPLETE_SCAN_RESULT_ID.toString(),
                    "--report-json", reportsJson.toString());
            Assertions.assertEquals(FAILED.getCode(), res);
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate JSON-defined reports for specific PHP smoke medium scan results using extended filters")
    public void generateJsonDefinedFilteredReportsForSpecificScan() {
        try (TempFile reportsFolder = TempFile.createFolder();
             TempFile reportsJson = TempFile.createFile()) {
            copyInputStreamToFile(getResourceStream("json/scan/reports/reports.5.json"), reportsJson.toFile());

            Integer res = new CommandLine(new Plugin()).execute(
                    "generate-report",
                    "--url", CONNECTION().getUrl(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--token", CONNECTION().getToken(),
                    "--output", reportsFolder.toString(),
                    "--project-name", PHP_SMOKE.getName(),
                    "--scan-result-id", LATEST_COMPLETE_SCAN_RESULT_ID.toString(),
                    "--report-json", reportsJson.toString());
            Assertions.assertEquals(SUCCESS.getCode(), res);
            checkReports(reportsJson.toPath(), reportsFolder.toPath());
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate reports with- and without DFD and glossary")
    public void generateReportsWithAndWithoutDfdAndGlossary() {
        try (TempFile reportsFolder = TempFile.createFolder()) {
            Path reportMin = reportsFolder.toPath().resolve("minimal.html");
            Path reportMax = reportsFolder.toPath().resolve("maximum.html");
            Path reportDfd = reportsFolder.toPath().resolve("dfd.html");
            Path reportGlossary = reportsFolder.toPath().resolve("glossary.html");

            for (Path report : new Path[]{reportMin, reportMax, reportDfd, reportGlossary}) {
                List<String> args = new ArrayList<>(Arrays.asList(
                        "generate-report",
                        "--url", CONNECTION().getUrl(),
                        "--truststore", CA_PEM_FILE.toString(),
                        "--token", CONNECTION().getToken(),
                        "--output", reportsFolder.toString(),
                        "--project-name", PHP_SMOKE.getName(),
                        "--scan-result-id", LATEST_COMPLETE_SCAN_RESULT_ID.toString(),
                        "--report-file", report.getFileName().toString(),
                        "--report-template", "Scan results report"));
                if (report.equals(reportMax) || report.equals(reportDfd)) args.add("--report-include-dfd");
                if (report.equals(reportMax) || report.equals(reportGlossary)) args.add("--report-include-glossary");
                Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
                Assertions.assertEquals(SUCCESS.getCode(), res);
            }
            Assertions.assertTrue(reportMin.toFile().length() < reportDfd.toFile().length());
            Assertions.assertTrue(reportMin.toFile().length() < reportGlossary.toFile().length());
            Assertions.assertTrue(reportMin.toFile().length() < reportMax.toFile().length());

            Assertions.assertTrue(reportDfd.toFile().length() < reportMax.toFile().length());
            Assertions.assertTrue(reportGlossary.toFile().length() < reportMax.toFile().length());
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate SARIF report")
    public void generateSarifReport() {
        try (TempFile reportsFolder = TempFile.createFolder()) {
            Path report = reportsFolder.toPath().resolve("sarif.json");

            List<String> args = new ArrayList<>(Arrays.asList(
                    "generate-report",
                    "--url", CONNECTION().getUrl(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--token", CONNECTION().getToken(),
                    "--output", reportsFolder.toString(),
                    "--project-name", PHP_SMOKE.getName(),
                    "--scan-result-id", LATEST_COMPLETE_SCAN_RESULT_ID.toString(),
                    "--sarif-report-file", report.getFileName().toString()));
            Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
            Assertions.assertEquals(SUCCESS.getCode(), res);

            SarifSchema210 sarif = createObjectMapper().readValue(report.toFile(), SarifSchema210.class);
            Assertions.assertEquals("Positive Technologies", sarif.getRuns().get(0).getTool().getDriver().getOrganization());
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate filtered JSON-defined SARIF reports")
    public void generateFilteredSarifReports() {
        try (TempFile reportsFolder = TempFile.createFolder();
             TempFile reportsJson = TempFile.createFile()) {
            Path reportFull = reportsFolder.toPath().resolve("sarif.full.json");
            Path reportLow = reportsFolder.toPath().resolve("sarif.low.json");
            Path reportMedium = reportsFolder.toPath().resolve("sarif.medium.json");

            copyInputStreamToFile(getResourceStream("json/scan/reports/reports.6.json"), reportsJson.toFile());

            Integer res = new CommandLine(new Plugin()).execute(
                    "generate-report",
                    "--url", CONNECTION().getUrl(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--token", CONNECTION().getToken(),
                    "--output", reportsFolder.toString(),
                    "--project-name", PHP_SMOKE.getName(),
                    "--scan-result-id", LATEST_COMPLETE_SCAN_RESULT_ID.toString(),
                    "--report-json", reportsJson.toString());
            Assertions.assertEquals(SUCCESS.getCode(), res);

            Assertions.assertTrue(reportFull.toFile().length() > reportLow.toFile().length());
            ObjectMapper mapper = createObjectMapper();
            SarifSchema210 sarifFull = mapper.readValue(reportFull.toFile(), SarifSchema210.class);
            SarifSchema210 sarifLow = mapper.readValue(reportLow.toFile(), SarifSchema210.class);
            SarifSchema210 sarifMedium = mapper.readValue(reportMedium.toFile(), SarifSchema210.class);
            Assertions.assertNotEquals(sarifLow.getRuns().get(0).getResults().size(), 0);
            Assertions.assertNotEquals(sarifFull.getRuns().get(0).getResults().size(), 0);
            Assertions.assertNotEquals(sarifMedium.getRuns().get(0).getResults().size(), 0);
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Generate GIIF report")
    public void generateGiifReport() {
        try (TempFile reportsFolder = TempFile.createFolder()) {
            Path report = reportsFolder.toPath().resolve("giif.json");

            List<String> args = new ArrayList<>(Arrays.asList(
                    "generate-report",
                    "--url", CONNECTION().getUrl(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--token", CONNECTION().getToken(),
                    "--output", reportsFolder.toString(),
                    "--project-name", PHP_SMOKE.getName(),
                    "--scan-result-id", LATEST_COMPLETE_SCAN_RESULT_ID.toString(),
                    "--giif-report-file", report.getFileName().toString()));
            Integer res = new CommandLine(new Plugin()).execute(args.toArray(new String[0]));
            Assertions.assertEquals(SUCCESS.getCode(), res);

            SonarGiif.SonarGiifReport giifReport = createObjectMapper().readValue(report.toFile(), SonarGiif.SonarGiifReport.class);
            Assertions.assertFalse(giifReport.getIssues().isEmpty());
        }
    }

    /**
     * Functio checks if all the JSON-defined reports are present in destination folder
     * @param reportsJson JSON-defined set of reports
     * @param reportsFolder Reports destination folder
     */
    @SneakyThrows
    protected static void checkReports(@NonNull final Path reportsJson, @NonNull final Path reportsFolder) {
        Reports reports = createObjectMapper().readValue(reportsJson.toFile(), Reports.class);
        reports.getReport().forEach((r) -> {
            File report = reportsFolder.resolve(r.getFileName()).toFile();
            log.trace("Check {} report file exists", report.getName());
            Assertions.assertTrue(report.exists());
        });
        reports.getRaw().forEach((r) -> {
            File report = reportsFolder.resolve(r.getFileName()).toFile();
            log.trace("Check {} raw data file exists", report.getName());
            Assertions.assertTrue(report.exists());
        });
        reports.getSarif().forEach((r) -> {
            File report = reportsFolder.resolve(r.getFileName()).toFile();
            log.trace("Check {} SARIF report file exists", report.getName());
            Assertions.assertTrue(report.exists());
        });
        reports.getSonarGiif().forEach((r) -> {
            File report = reportsFolder.resolve(r.getFileName()).toFile();
            log.trace("Check {} SonarQube GIIF report file exists", report.getName());
            Assertions.assertTrue(report.exists());
        });
    }
}