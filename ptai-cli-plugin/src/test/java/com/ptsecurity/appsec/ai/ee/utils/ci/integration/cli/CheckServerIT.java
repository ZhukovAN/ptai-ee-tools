package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.helpers.CertificateHelper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemErr;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOutNormalized;
import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.FAILED;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertEquals(SUCCESS.getCode(), res);
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
        assertEquals(SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Insecure connect without valid CA certificate")
    public void insecureConnectWithoutCA() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--insecure");
        assertEquals(SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail secure connect without valid CA certificates")
    public void failSecureConnectWithoutCA() {
        String outText = tapSystemOutNormalized(() -> {
            Integer res = new CommandLine(new Plugin()).execute(
                    "check-server",
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", DUMMY_CA_PEM_FILE.toString());
            assertEquals(FAILED.getCode(), res);
        });
        assertTrue(outText.contains(Resources.i18n_ast_settings_server_check_message_sslhandshakefailed()));
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail connect with invalid token")
    public void failConnectWithInvalidToken() {
        String error = tapSystemErr(() -> {
            String outText = tapSystemOutNormalized(() -> {
                Integer res = new CommandLine(new Plugin()).execute(
                        "check-server",
                        "--url", CONNECTION().getUrl(),
                        "--truststore", CA_PEM_FILE.toString(),
                        "--token", CONNECTION().getToken() + UUID.randomUUID());
                assertEquals(FAILED.getCode(), res);
            });
            assertTrue(outText.contains(Resources.i18n_ast_settings_server_check_message_unauthorized()));
        });
        assertEquals("", error);
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail non-existent host connection")
    public void authenticateFailNonExistentHost() {
        String outText = tapSystemOutNormalized(() -> {
            Integer res = new CommandLine(new Plugin()).execute(
                    "check-server",
                    "--url", "https://" + UUID.randomUUID().toString(),
                    "--token", CONNECTION().getToken(),
                    "--insecure");
            assertEquals(FAILED.getCode(), res);
        });
        assertTrue(outText.contains(Resources.i18n_ast_settings_server_check_message_connectionfailed()));
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid service connection")
    public void authenticateFailInvalidHost() {
        URL ptaiUrl = new URL(CONNECTION().getUrl());
        URL invalidServiceUrl = new URL(ptaiUrl.getProtocol(), ptaiUrl.getHost(), 9443, ptaiUrl.getFile());

        String outText = tapSystemOutNormalized(() -> {
            Integer res = new CommandLine(new Plugin()).execute(
                    "check-server",
                    "--url", invalidServiceUrl.toString(),
                    "--token", CONNECTION().getToken(),
                    "--insecure");
            assertEquals(FAILED.getCode(), res);
        });
        assertTrue(outText.contains(Resources.i18n_ast_settings_server_check_message_endpointnotfound()));
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid port connection")
    public void authenticateFailInvalidPort() {
        URL ptaiUrl = new URL(CONNECTION().getUrl());
        URL invalidServiceUrl = new URL(ptaiUrl.getProtocol(), ptaiUrl.getHost(), 65535, ptaiUrl.getFile());
        String outText = tapSystemOutNormalized(() -> {
            Integer res = new CommandLine(new Plugin()).execute(
                    "check-server",
                    "--url", invalidServiceUrl.toString(),
                    "--token", CONNECTION().getToken(),
                    "--insecure");
            assertEquals(FAILED.getCode(), res);
        });
        assertTrue(outText.contains(Resources.i18n_ast_settings_server_check_message_connectionfailed()));
    }

    @SneakyThrows
    @Test
    @DisplayName("Fail invalid PEM data")
    public void authenticateFailInvalidCertificate() {
        String outText = tapSystemOutNormalized(() -> {
            try (TempFile pem = TempFile.createFile()) {
                String pemData = FileUtils.readFileToString(CA_PEM_FILE.toFile(), StandardCharsets.UTF_8);
                pemData = pemData.replaceAll("9", "2023");
                FileUtils.writeStringToFile(pem.toFile(), pemData, StandardCharsets.UTF_8);
                Integer res = new CommandLine(new Plugin()).execute(
                        "check-server",
                        "--url", CONNECTION().getUrl(),
                        "--token", CONNECTION().getToken(),
                        "--truststore", pem.toString());
                assertEquals(FAILED.getCode(), res);
            }
        });
        assertTrue(outText.contains(Resources.i18n_ast_settings_server_ca_pem_message_parse_failed_details()));
    }
}