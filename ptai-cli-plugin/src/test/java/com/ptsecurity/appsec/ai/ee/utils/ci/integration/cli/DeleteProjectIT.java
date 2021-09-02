package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.CheckServerTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.*;
import picocli.CommandLine;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.RU;

@DisplayName("Project deletion tests")
@Tag("integration")
class DeleteProjectIT extends BaseJsonIT {

    @Test
    @DisplayName("Create and then remove single project by its name")
    public void createDeleteSingleProjectByName() {
        scanPhpSettings.setProjectName(newProjectName);
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(CONNECTION_SETTINGS));
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        projectTasks.setupFromJson(scanPhpSettings, scanPolicy);
        Assertions.assertNotNull(projectTasks.searchProject(newProjectName));
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name", newProjectName,
                "--yes",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--user", USER,
                "--password", PASSWORD);
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertNull(projectTasks.searchProject(newProjectName));
    }
    @Test
    @DisplayName("Create and then remove single project by its ID")
    public void createDeleteSingleProjectById() {
        scanPhpSettings.setProjectName(newProjectName);
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(CONNECTION_SETTINGS));
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        projectTasks.setupFromJson(scanPhpSettings, scanPolicy);
        UUID projectId = projectTasks.searchProject(newProjectName);
        Assertions.assertNotNull(projectId);
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-id", projectId.toString(),
                "--yes",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--user", USER,
                "--password", PASSWORD);
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertNull(projectTasks.searchProject(newProjectName));
    }

    @Test
    @DisplayName("Create and then remove multiple projects by regular expression")
    public void createDeleteMultipleProjectsByRegexp() {
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(CONNECTION_SETTINGS));
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        List<Pair<String, UUID>> projects = new ArrayList<>();
        for (int i = 1; i <= 5 ; i++) {
            String projectName = newProjectName + "-" + String.valueOf(i);
            scanPhpSettings.setProjectName(projectName);
            projectTasks.setupFromJson(scanPhpSettings, scanPolicy);
            UUID projectId = projectTasks.searchProject(projectName);
            Assertions.assertNotNull(projectId);
            projects.add(Pair.of(projectName, projectId));
        }
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name-regexp", newProjectName + "-[0-9]",
                "--yes",
                "--url", URL,
                "--truststore", PEM.toString(),
                "--user", USER,
                "--password", PASSWORD);
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        for (Pair<String, UUID> project : projects)
            Assertions.assertNull(projectTasks.searchProject(project.getLeft()));
    }
}