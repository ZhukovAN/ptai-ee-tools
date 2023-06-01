package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.misc.tools.TempFile;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.ID.PHP_SMOKE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.getTemplate;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.FAILED;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.SUCCESS;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.GENERIC_POLICY;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.setupProjectFromTemplate;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;
import static org.apache.commons.io.FileUtils.copyInputStreamToFile;

@DisplayName("Check UI-defined AST scans")
@Slf4j
@Tag("integration")
class UiAstIT extends BaseCliIT {
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("AST of existing project")
    void scanExistingProject() {
        Project project = BaseAstIT.setupProjectFromTemplate(PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", project.getName(),
                "--input", project.getCode().toString(),
                "--truststore", CA_PEM_FILE.toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken());
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }

    @Test
    @Tag("integration")
    @DisplayName("Fail AST of existing project with no source code included")
    void failIfNoSourcesIncluded() {
        Project project = BaseAstIT.setupProjectFromTemplate(PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", project.getName(),
                "--input", project.getCode().toString(),
                "--truststore", CA_PEM_FILE.toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--includes", "**/*.java",
                "--excludes", "**/*");
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Fail AST of policy violating project")
    void failIfPolicyViolated() {
        Project project = setupProjectFromTemplate(PHP_SMOKE, GENERIC_POLICY.getJson());
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", project.getName(),
                "--input", project.getCode().toString(),
                "--truststore", CA_PEM_FILE.toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--fail-if-failed");
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @Test
    @Tag("integration")
    @DisplayName("Fail AST of missing project")
    void failIfProjectMissing() {
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", randomProjectName(),
                "--input", getTemplate(PHP_SMOKE).getCode().toString(),
                "--truststore", CA_PEM_FILE.toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken());
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @Test
    @Tag("integration")
    @DisplayName("Fail AST of existing project without custom truststore")
    void failWithoutTruststore() {
        Project project = setupProjectFromTemplate(PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", project.getName(),
                "--input", project.getCode().toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", DUMMY_CA_PEM_FILE.toString());
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Insecure AST of existing project without custom truststore")
    void scanInsecureWithoutTruststore() {
        Project project = setupProjectFromTemplate(PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", project.getName(),
                "--input", project.getCode().toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--insecure");
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Twice AST of existing project to test report overwrite")
    void rewriteExistingReport() {
        try (TempFile reportsFolder = TempFile.createFolder()) {
            Project project = setupProjectFromTemplate(PHP_SMOKE);
            Path report = reportsFolder.toPath().resolve("owasp.en.html");
            Integer res = new CommandLine(new Plugin()).execute(
                    "ui-ast",
                    "--project", project.getName(),
                    "--input", project.getCode().toString(),
                    "--output", reportsFolder.toString(),
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--report-file", report.getFileName().toString(),
                    "--report-template", "Scan results report");
            Assertions.assertEquals(SUCCESS.getCode(), res);
            Assertions.assertTrue(report.toFile().exists());
            BasicFileAttributes attr = Files.readAttributes(report, BasicFileAttributes.class);
            FileTime fileTime = attr.creationTime();

            res = new CommandLine(new Plugin()).execute(
                    "ui-ast",
                    "--project", project.getName(),
                    "--input", project.getCode().toString(),
                    "--output", reportsFolder.toString(),
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--report-file", report.getFileName().toString(),
                    "--report-template", "Scan results report");
            Assertions.assertEquals(SUCCESS.getCode(), res);
            Assertions.assertTrue(report.toFile().exists());
            attr = Files.readAttributes(report, BasicFileAttributes.class);
            Assertions.assertNotEquals(fileTime, attr.lastModifiedTime());
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("AST existing project with multiple JSON-defined reports")
    void generateJsonDefinedReports() {
        try (TempFile reportsFolder = TempFile.createFolder();
             TempFile reportsJson = TempFile.createFile()) {
            Project project = setupProjectFromTemplate(PHP_SMOKE);
            copyInputStreamToFile(getResourceStream("json/scan/reports/reports.1.json"), reportsJson.toFile());

            Integer res = new CommandLine(new Plugin()).execute(
                    "ui-ast",
                    "--project", project.getName(),
                    "--input", project.getCode().toString(),
                    "--output", reportsFolder.toString(),
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--report-json", reportsJson.toString());
            Assertions.assertEquals(SUCCESS.getCode(), res);
            GenerateReportIT.checkReports(reportsJson.toPath(), reportsFolder.toPath());
        }
    }

    @SneakyThrows
    @Test
    @Tag("integration")
    @DisplayName("Fail AST existing project with bad JSON-defined reports")
    public void failInvalidReportsJson() {
        try (TempFile reportsJson = TempFile.createFile()) {
            Project project = setupProjectFromTemplate(PHP_SMOKE);
            copyInputStreamToFile(getResourceStream("json/scan/reports/reports.2.json"), reportsJson.toFile());
            Integer res = new CommandLine(new Plugin()).execute(
                    "ui-ast",
                    "--project", project.getName(),
                    "--input", project.getCode().toString(),
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--report-json", reportsJson.toString());
            Assertions.assertEquals(FAILED.getCode(), res);
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @Tag("integration")
    @DisplayName("Fail AST existing project with JSON-defined reports with missing templates")
    public void failMissingJsonDefinedReportTemplates() {
        try (TempFile reportsJson = TempFile.createFile()) {
            Project project = setupProjectFromTemplate(PHP_SMOKE);
            copyInputStreamToFile(getResourceStream("json/scan/reports/reports.3.json"), reportsJson.toFile());
            Integer res = new CommandLine(new Plugin()).execute(
                    "ui-ast",
                    "--project", project.getName(),
                    "--input", project.getCode().toString(),
                    "--url", CONNECTION().getUrl(),
                    "--token", CONNECTION().getToken(),
                    "--truststore", CA_PEM_FILE.toString(),
                    "--report-json", reportsJson.toString());
            Assertions.assertEquals(FAILED.getCode(), res);
        }
    }

    @Test
    @Tag("integration")
    @DisplayName("Asynchronous AST of existing project")
    void scanProjectAsync() {
        Project project = setupProjectFromTemplate(PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", project.getName(),
                "--input", project.getCode().toString(),
                "--truststore", CA_PEM_FILE.toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--async");
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }

    @Test
    @Tag("integration")
    @DisplayName("Asynchronous AST of missing project with custom truststore")
    void failMissingProjectAsync() {
        Project project = setupProjectFromTemplate(PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", randomProjectName(),
                "--input", project.getCode().toString(),
                "--truststore", CA_PEM_FILE.toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--async");
        Assertions.assertEquals(FAILED.getCode(), res);
    }

    @Test
    @Tag("integration")
    @DisplayName("Asynchronous AST of existing project without custom truststore")
    void failWithoutTruststoreAsync() {
        Project project = setupProjectFromTemplate(PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "ui-ast",
                "--project", project.getName(),
                "--input", project.getCode().toString(),
                "--url", CONNECTION().getUrl(),
                "--token", CONNECTION().getToken(),
                "--truststore", DUMMY_CA_PEM_FILE.toString());
        Assertions.assertEquals(FAILED.getCode(), res);
    }
}