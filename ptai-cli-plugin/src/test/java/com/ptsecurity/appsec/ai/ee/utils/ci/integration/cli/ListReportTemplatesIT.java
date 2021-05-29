package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

@DisplayName("Report templates list read tests")
@Tag("integration-legacy")
class ListReportTemplatesIT extends BaseIT {

    @Test
    @DisplayName("Read russian report template names")
    public void testReportTemplatesRu() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--locale", Reports.Locale.RU.name());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Read english report template names")
    public void testReportTemplatesEn() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--locale", Reports.Locale.EN.name());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Read korean report template names")
    public void testReportTemplatesKo() {
        Integer res = new CommandLine(new Plugin()).execute(
                "list-report-templates",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--locale", "KO");
        Assertions.assertEquals(BaseCommand.ExitCode.INVALID_INPUT.getCode(), res);
    }

}