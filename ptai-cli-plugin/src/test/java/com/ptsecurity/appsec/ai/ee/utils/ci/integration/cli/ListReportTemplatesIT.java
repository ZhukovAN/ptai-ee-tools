package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import picocli.CommandLine;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.RU;
import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;

@DisplayName("Report templates list read tests")
@Tag("integration")
@Slf4j
class ListReportTemplatesIT extends BaseCliIT {
    @Test
    @DisplayName("Read russian report template names")
    public void readReportTemplatesRu() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--locale", RU.name());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Read english report template names")
    public void readReportTemplatesEn() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--locale", EN.name());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Fail reading korean report template names")
    public void failReadReportTemplatesKo() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", CA_PEM_FILE.toString(),
                "--locale", "KO");
        Assertions.assertEquals(BaseCommand.ExitCode.INVALID_INPUT.getCode(), res);
    }
}