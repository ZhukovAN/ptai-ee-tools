package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.AuthScopeType;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanResult;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Stage;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Data.Format.JSON;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Data.Format.XML;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Locale.RU;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Report.Format.HTML;

@DisplayName("Report generation tests")
@Tag("integration-legacy")
class GenerateReportIT extends BaseIT {
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
        UUID scanResultId = getLatestCompleteScanResults(EXISTING_PROJECT);
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
            Path folder = Paths.get(REPORT_FOLDER).resolve(UUID.randomUUID().toString());
            List<String> args = new ArrayList<>(Arrays.asList(
                    "generate-report",
                    "--url", PTAI_URL,
                    "--truststore", PEM_PATH,
                    "--token", TOKEN,
                    "--output", folder.toString(),
                    "--project-name", EXISTING_PROJECT));
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
        Utils utils = Utils.builder()
                .console(System.out)
                .url(PTAI_URL)
                .token(TOKEN)
                .build();
        String pem = new String(Files.readAllBytes(Paths.get(PEM_PATH)), StandardCharsets.UTF_8);
        utils.setCaCertsPem(pem);
        utils.init();

        UUID projectId = utils.searchProject(project);
        List<ScanResult> results = utils.getProjectsApi().apiProjectsProjectIdScanResultsGet(projectId, AuthScopeType.VIEWER);
        ScanResult result = results.stream()
                .filter(r -> r.getProgress().getStage().equals(Stage.DONE))
                .findAny().orElseThrow(() -> new IllegalArgumentException("project"));
        return result.getId();
    }

    @Test
    @DisplayName("Fail when duplicate file names are used")
    public void testDuplicateFileNamesProcessing() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--output", REPORT_FOLDER,
                "--project-name", EXISTING_PROJECT,
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
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--output", REPORT_FOLDER,
                "--project-name", EXISTING_PROJECT,
                "--report-template", "Отчет OWASP Top 10 2017 ",
                "--report-file", "owasp.ru.html",
                "--report-locale", EN.name(),
                "--report-format", HTML.name());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Generate multiple JSON-defined reports for specific app01 scan results")
    public void testLatestJsonDefinedReportsGeneration() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--output", REPORT_FOLDER,
                "--project-name", EXISTING_PROJECT,
                "--scan-result-id", getLatestCompleteScanResults(EXISTING_PROJECT).toString(),
                "--report-json", getResourcePath("json/reports.1.json"));
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Generate invalid JSON-defined reports for specific app01 scan results")
    public void testLatestInvalidJsonDefinedReportsGeneration() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--output", REPORT_FOLDER,
                "--project-name", EXISTING_PROJECT,
                "--scan-result-id", getLatestCompleteScanResults(EXISTING_PROJECT).toString(),
                "--report-json", getResourcePath("json/reports.4.json"));
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Generate JSON-defined reports for specific app01 scan results using extended filters")
    public void testLatestExtendedJsonDefinedReportsGeneration() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN,
                "--output", REPORT_FOLDER,
                "--project-name", EXISTING_PROJECT,
                "--scan-result-id", getLatestCompleteScanResults(EXISTING_PROJECT).toString(),
                "--report-json", getResourcePath("json/reports.5.json"));
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

}