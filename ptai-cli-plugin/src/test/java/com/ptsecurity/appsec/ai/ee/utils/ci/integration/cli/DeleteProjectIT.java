package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.util.ArrayList;
import java.util.List;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.ID.PHP_SMOKE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.getTemplate;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.randomClone;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.SUCCESS;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.setupProjectFromTemplate;

@DisplayName("Project deletion tests")
@Tag("integration")
@Slf4j
class DeleteProjectIT extends BaseCliIT {
    @Test
    @DisplayName("Create and then remove single project by its name")
    public void createDeleteSingleProjectByName() {
        Project project = setupProjectFromTemplate(PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name", project.getName(),
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--insecure",
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(SUCCESS.getCode(), res);
        Assertions.assertNull(projectTasks.searchProject(project.getName()));
    }

    @Test
    @DisplayName("Create and then remove single project by its ID")
    public void createDeleteSingleProjectById() {
        Project project = setupProjectFromTemplate(ProjectTemplate.ID.PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-id", project.getId().toString(),
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(SUCCESS.getCode(), res);
        Assertions.assertNull(projectTasks.searchProject(project.getName()));
    }

    @Test
    @DisplayName("Create and then remove multiple projects by regular expression")
    public void createDeleteMultipleProjectsByRegexp() {
        List<Project> projects = new ArrayList<>();
        ProjectTemplate phpSmoke = getTemplate(PHP_SMOKE);
        for (int i = 1; i <= 5 ; i++) {
            ProjectTemplate project = randomClone(PHP_SMOKE, phpSmoke.getName() + "-" + i);
            projects.add(BaseAstIT.setupProject(project));
        }
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name-regexp", phpSmoke.getName() + "-[0-9]",
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(SUCCESS.getCode(), res);
        for (Project project : projects)
            Assertions.assertNull(projectTasks.searchProject(project.getName()));
    }

    @Test
    @DisplayName("Delete all GUID-like projects")
    public void deleteAllTestProjects() {
        setupProjectFromTemplate(ProjectTemplate.ID.PHP_SMOKE);
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name-regexp", ".*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}.*",
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(SUCCESS.getCode(), res);
    }
}