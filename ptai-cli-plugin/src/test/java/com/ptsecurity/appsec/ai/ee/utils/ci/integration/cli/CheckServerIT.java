package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.FAILED;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.SUCCESS;

@DisplayName("Server availability check tests")
@Tag("integration")
@Slf4j
class CheckServerIT extends BaseCliIT {
    @Test
    @DisplayName("Secure connect with valid CA certificate")
    public void secureConnect() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken());
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Insecure connect with valid CA certificates")
    public void insecureConnectWithCA() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken(),
                "--insecure");
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Insecure connect without valid CA certificate")
    public void insecureConnectWithoutCA() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--insecure");
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Fail secure connect without valid CA certificates")
    public void failSecureConnectWithoutCA() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", DUMMY_CA_PEM_FILE.toString());
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Fail connect with invalid token")
    public void failConnectWithInvalidToken() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--token", CONNECTION().getToken() + UUID.randomUUID());
        Assertions.assertEquals(FAILED.getCode(), res);
    }
}