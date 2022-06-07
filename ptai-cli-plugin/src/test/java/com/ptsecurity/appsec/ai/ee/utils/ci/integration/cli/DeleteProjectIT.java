package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsTestHelper;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.PHP_SMOKE_MEDIUM;

@DisplayName("Project deletion tests")
@Tag("integration")
class DeleteProjectIT extends BaseJsonIT {

    @Test
    @DisplayName("Create and then remove single project by its name")
    public void createDeleteSingleProjectByName() {
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE_MEDIUM.getSettings()).randomizeProjectName();
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(CONNECTION_SETTINGS()));
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        projectTasks.setupFromJson(settings.serialize(), scanPolicy);
        Assertions.assertNotNull(projectTasks.searchProject(settings.getProjectName()));
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name", settings.getProjectName(),
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertNull(projectTasks.searchProject(settings.getProjectName()));
    }
    @Test
    @DisplayName("Create and then remove single project by its ID")
    public void createDeleteSingleProjectById() {
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE_MEDIUM.getSettings()).randomizeProjectName();
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(CONNECTION_SETTINGS()));
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        projectTasks.setupFromJson(settings.serialize(), scanPolicy);
        UUID projectId = projectTasks.searchProject(settings.getProjectName());
        Assertions.assertNotNull(projectId);
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-id", projectId.toString(),
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        Assertions.assertNull(projectTasks.searchProject(settings.getProjectName()));
    }

    @Test
    @DisplayName("Create and then remove multiple projects by regular expression")
    public void createDeleteMultipleProjectsByRegexp() {
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(CONNECTION_SETTINGS()));
        ProjectTasks projectTasks = new Factory().projectTasks(client);
        List<Pair<String, UUID>> projects = new ArrayList<>();
        JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE_MEDIUM.getSettings()).randomizeProjectName();
        String projectNamePrefix = settings.getProjectName();
        for (int i = 1; i <= 5 ; i++) {
            settings.setProjectName(projectNamePrefix + "-" + i);
            projectTasks.setupFromJson(settings.serialize(), scanPolicy);
            UUID projectId = projectTasks.searchProject(settings.getProjectName());
            Assertions.assertNotNull(projectId);
            projects.add(Pair.of(settings.getProjectName(), projectId));
        }
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name-regexp", projectNamePrefix + "-[0-9]",
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
        for (Pair<String, UUID> project : projects)
            Assertions.assertNull(projectTasks.searchProject(project.getLeft()));
    }

    @Test
    @DisplayName("Delete all junit-GUID-like projects")
    public void deleteAllTestProjects() {
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name-regexp", "junit-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(BaseCommand.ExitCode.SUCCESS.getCode(), res);
    }

}