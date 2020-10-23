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
        JAVA_SETTINGS.setProjectName(NEW_PROJECT_NAME);
        saveJsons();

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--settings-json", JAVA_SETTINGS_PATH.toString(),
                "--policy-json", POLICY_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
/*
        JAVA_SETTINGS.setDownloadDependencies(false);
        saveJsons();
        res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--settings-json", JAVA_SETTINGS_PATH.toString(),
                "--policy-json", POLICY_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);

        res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--output", TEMP_REPORT_FOLDER.toPath().toString(),
                "--settings-json", JAVA_SETTINGS_PATH.toString(),
                "--policy-json", POLICY_PATH.toString());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);*/
    }

    @SneakyThrows
    @Test
    @DisplayName("Execute JSON-defined AST of new project")
    public void testCSharpJsonAst() {
        JAVA_SETTINGS.setProjectName(NEW_PROJECT_NAME);
        saveJsons();

        int res = new CommandLine(new Plugin()).execute(
                "json-ast",
                "--url", PTAI_URL,
                "--truststore", PEM_PATH.toString(),
                "--token", TOKEN,
                "--input", TEMP_SOURCES_FOLDER.toPath().toString(),
                "--settings-json", TEMP_JSON_FOLDER.toPath().resolve("settings.csharp.original").toString());
        Assertions.assertEquals(BaseCommand.ExitCode.FAILED.getCode(), res);
    }
}