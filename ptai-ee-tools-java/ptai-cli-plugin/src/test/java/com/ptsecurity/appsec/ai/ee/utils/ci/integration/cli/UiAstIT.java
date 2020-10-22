package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import lombok.SneakyThrows;
import org.junit.jupiter.api.*;
import picocli.CommandLine;

@DisplayName("Check UI-defined AST scans")
class UiAstIT extends BaseIT {
    @Test
    @DisplayName("Show usage of UI-defined AST")
    public void testUiAstShowUsage() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast");
        Assertions.assertEquals(BaseCommand.ExitCode.INVALID_INPUT.getCode(), res);
    }

    @Test
    @DisplayName("Execute UI-defined AST of existing project without custom truststore")
    public void testUiAstWithoutTruststore() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Twice execute UI-defined AST of existing project to test report overwrite")
    public void testUiAst() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--report-template", "OWASP top 10 2017 report",
                "--report-format", "JSON",
                "--report-locale", "EN");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
        res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--report-template", "OWASP top 10 2017 report",
                "--report-format", "JSON",
                "--report-locale", "EN");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Test existing project scan with report generation")
    public void testUiAstReports() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--report-template", "OWASP top 10 2017 report",
                "--report-format", "HTML",
                "--report-locale", "EN");
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @SneakyThrows
    @Test
    public void testNamedReportDefinitionProcessing() {
        BaseCommand.NamedReportDefinition[] reports = new BaseCommand.NamedReportDefinition[2];
        reports[0] = BaseCommand.NamedReportDefinition.builder()
                .format(BaseCommand.ReportDefinition.Format.JSON)
                .locale(BaseCommand.ReportDefinition.Locale.EN)
                .template("OWASP top 10 2017 report")
                .name("owasp.top.10.en.json")
                .build();
        reports[1] = BaseCommand.NamedReportDefinition.builder()
                .format(BaseCommand.ReportDefinition.Format.XML)
                .locale(BaseCommand.ReportDefinition.Locale.EN)
                .template("OWASP top 10 2017 report")
                .name("owasp.top.10.en.xml")
                .build();

        String jsonStr = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(reports);
        System.out.println(jsonStr);

        reports = BaseCommand.NamedReportDefinition.load(jsonStr);
        for (BaseCommand.NamedReportDefinition report : reports)
            System.out.println(report.getName());
    }

    @Test
    @DisplayName("Test existing project scan with multiple JSON-defined reports generation")
    public void testUiAstJsonDefinedReports() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--report-json", REPORTS_GOOD_JSON_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Test existing project scan with bad JSON-defined reports")
    public void testUiAstBadJsonDefinedReports() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--report-json", REPORTS_BAD_JSON_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.ERROR.getCode(), res);
    }

    @Test
    @DisplayName("Test existing project scan with JSON-defined reports with missing templates")
    public void testUiAstMissingJsonDefinedReports() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--report-json", REPORTS_MISSING_JSON_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.ERROR.getCode(), res);
    }

    @Test
    @DisplayName("Execute asynchronous UI-defined AST of existing project without custom truststore")
    public void testAsyncUiAstWithoutTruststore() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--token", TOKEN,
                "--async");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }
}