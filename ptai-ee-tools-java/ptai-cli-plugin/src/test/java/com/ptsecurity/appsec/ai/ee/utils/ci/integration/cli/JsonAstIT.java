package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

@DisplayName("Check JSON-defined AST scans")
class JsonAstIT extends BaseIT {

    @SneakyThrows
    @Test
    @DisplayName("Execute JSON-defined AST of new project")
    public void testJsonAst() {
        SETTINGS.setProjectName(NEW_PROJECT_NAME);
        saveJsons();

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--settings-json", SETTINGS_PATH.toString(),
                "--policy-json", POLICY_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
/*
        SETTINGS.setDownloadDependencies(false);
        saveJsons();
        res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--settings-json", SETTINGS_PATH.toString(),
                "--policy-json", POLICY_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);

        res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--settings-json", SETTINGS_PATH.toString(),
                "--policy-json", POLICY_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);*/
    }
}