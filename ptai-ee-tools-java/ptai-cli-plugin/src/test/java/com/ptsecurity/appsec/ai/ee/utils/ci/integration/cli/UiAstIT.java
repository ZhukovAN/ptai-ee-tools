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

@DisplayName("Check UI-defined AST scans")
class UiAstIT extends BaseIT {
    @Test
    @DisplayName("Show usage of UI-defined AST")
    public void testUiAstShowUsage() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast");
        Assertions.assertEquals(BaseAst.ExitCode.INVALID_INPUT.getCode(), res);
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
        Assertions.assertEquals(BaseAst.ExitCode.FAILED.getCode(), res);
    }

    @Test
    @DisplayName("Execute UI-defined AST of existing project")
    public void testUiAst() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", EXISTING_PROJECT_NAME,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN);
        Assertions.assertEquals(BaseAst.ExitCode.FAILED.getCode(), res);
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
        Assertions.assertEquals(BaseAst.ExitCode.FAILED.getCode(), res);
    }
}