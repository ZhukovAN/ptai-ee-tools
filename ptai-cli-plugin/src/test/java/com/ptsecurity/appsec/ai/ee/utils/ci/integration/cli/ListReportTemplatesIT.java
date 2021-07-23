package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.RU;

@DisplayName("Report templates list read tests")
@Tag("integration-legacy")
class ListReportTemplatesIT extends BaseCliIT {

    @Test
    @DisplayName("Read russian report template names")
    public void testReportTemplatesRu() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--locale", RU.name());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Read english report template names")
    public void testReportTemplatesEn() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--locale", EN.name());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Fail reading korean report template names")
    public void testReportTemplatesKo() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--token", TOKEN,
                "--locale", "KO");
        Assertions.assertEquals(BaseCommand.ExitCode.INVALID_INPUT.getCode(), res);
    }

}