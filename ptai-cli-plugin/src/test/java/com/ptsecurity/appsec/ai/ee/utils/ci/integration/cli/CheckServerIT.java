package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.util.UUID;

@DisplayName("Server availability check tests")
@Tag("integration-legacy")
class CheckServerIT extends BaseIT {
    @Test
    @DisplayName("Connect with valid token")
    public void testGoodToken() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Insecure connect with CA certificates")
    public void testInsecureWithCaCertificate() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--insecure");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Insecure connect with valid token")
    public void testInsecureGoodToken() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", PTAI_URL,
                "--token", TOKEN,
                "--insecure");
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Secure connect without CA certificates")
    public void testWithoutCaCertificates() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", PTAI_URL,
                "--token", TOKEN);
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Connect with invalid token")
    public void testBadToken() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH,
                "--token", TOKEN + UUID.randomUUID());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }
}