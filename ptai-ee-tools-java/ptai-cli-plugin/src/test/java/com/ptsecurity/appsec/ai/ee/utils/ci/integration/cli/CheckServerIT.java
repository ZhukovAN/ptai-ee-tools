package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseAst;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

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
        Assertions.assertEquals(BaseAst.ExitCode.SUCCESS.getCode(), res);
    }

    @Test
    @DisplayName("Check server health with invalid token")
    public void testHealthCheckBadToken() {
        Integer res = new CommandLine(new Plugin()).execute(
                "check-server",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN + UUID.randomUUID());
        Assertions.assertEquals(BaseAst.ExitCode.ERROR.getCode(), res);
    }
}