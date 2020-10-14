package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseAst;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.util.UUID;

@DisplayName("Report generation tests")
class GenerateReportIT extends BaseIT {
    @Test
    @DisplayName("Generate latest app01 scan results report")
    public void testLatestReportGeneration() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--project-name", EXISTING_PROJECT_NAME,
                "--report-template", "Scan results report",
                "--report-locale", "en-US",
                "--report-format", "Json");
        Assertions.assertEquals(BaseAst.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Generate specific app01 scan results report")
    public void testSpecificReportGeneration() {
        Integer res = new CommandLine(new Plugin()).execute(
                "generate-report",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--project-name", EXISTING_PROJECT_NAME,
                "--scan-result-id", "e53a53e3-e80f-456d-a033-c67d0b574d5b",
                "--report-template", "OWASP top 10 2017 report",
                "--report-locale", "en-US",
                "--report-format", "Html");
        Assertions.assertEquals(BaseAst.ExitCode.SUCCESS.getCode(), res);
    }

}