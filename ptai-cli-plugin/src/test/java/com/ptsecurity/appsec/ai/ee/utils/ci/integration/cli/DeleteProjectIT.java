package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project.PHP_SMOKE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.ExitCode.SUCCESS;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.setup;

@DisplayName("Project deletion tests")
@Tag("integration")
@Slf4j
class DeleteProjectIT extends BaseCliIT {
    @Test
    @DisplayName("Create and then remove single project by its name")
    public void createDeleteSingleProjectByName() {
        Project phpSmokeClone = PHP_SMOKE.randomClone();
        setup(phpSmokeClone);
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name", phpSmokeClone.getName(),
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--insecure",
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(SUCCESS.getCode(), res);
        Assertions.assertNull(projectTasks.searchProject(phpSmokeClone.getName()));
    }

    @Test
    @DisplayName("Create and then remove single project by its ID")
    public void createDeleteSingleProjectById() {
        Project phpSmokeClone = PHP_SMOKE.randomClone();
        UUID projectId = setup(phpSmokeClone);
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-id", projectId.toString(),
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(SUCCESS.getCode(), res);
        Assertions.assertNull(projectTasks.searchProject(phpSmokeClone.getName()));
    }

    @Test
    @DisplayName("Create and then remove multiple projects by regular expression")
    public void createDeleteMultipleProjectsByRegexp() {
        List<Pair<String, UUID>> projects = new ArrayList<>();
        for (int i = 1; i <= 5 ; i++) {
            Project phpSmokeClone = PHP_SMOKE.randomClone();
            phpSmokeClone.setName(PHP_SMOKE.getName() + "-" + i);
            phpSmokeClone.getSettings().setProjectName(phpSmokeClone.getName());
            UUID projectId = setup(phpSmokeClone);
            projects.add(Pair.of(phpSmokeClone.getName(), projectId));
        }
        Integer res = new CommandLine(new Plugin()).execute(
                "delete-project",
                "--project-name-regexp", PHP_SMOKE.getName() + "-[0-9]",
                "--yes",
                "--url", CONNECTION().getUrl(),
                "--truststore", CA_PEM_FILE.toString(),
                "--user", CONNECTION().getUser(),
                "--password", CONNECTION().getPassword());
        Assertions.assertEquals(SUCCESS.getCode(), res);
        for (Pair<String, UUID> project : projects)
            Assertions.assertNull(projectTasks.searchProject(project.getLeft()));
    }

    @Test
    @DisplayName("Delete all GUID-like projects")
    public void deleteAllTestProjects() {
        setup(PHP_SMOKE.randomClone());
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