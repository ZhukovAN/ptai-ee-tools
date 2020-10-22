package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import org.junit.jupiter.api.*;
import picocli.CommandLine;

import java.util.UUID;

@DisplayName("Server check tests")
class CheckServerIT extends BaseIT {
    @Test
    @DisplayName("Check server health")
    public void testHealthCheck() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Check server health with invalid token")
    public void testHealthCheckBadToken() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN + UUID.randomUUID());
        Assertions.assertEquals(BaseCommand.ExitCode.ERROR.getCode(), res);
    }
}