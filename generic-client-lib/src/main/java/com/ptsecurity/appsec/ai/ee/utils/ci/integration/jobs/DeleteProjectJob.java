package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@SuperBuilder
public class DeleteProjectJob extends AbstractJob {
    public enum DeleteConfirmationStatus {
        YES, NO, ALL, TERMINATE
    }
    /**
     * Need to implement our own Runnable that throws checked Exception
     */
    @FunctionalInterface
    public interface Confirmation {
        DeleteConfirmationStatus confirm(final boolean singleProject, @NonNull final String name, @NonNull final UUID id);
    }

    @Getter
    protected Confirmation confirmation;

    @Getter
    protected String projectName;

    @Getter
    protected UUID projectId;

    @Getter
    protected String expression;

    @Override
    protected void init() throws GenericException {

    }

    @Override
    protected void unsafeExecute() throws GenericException {
        ProjectTasks tasks = new Factory().projectTasks(client);
        List<Pair<UUID, String>> projects;
        if (StringUtils.isNotEmpty(expression)) {
            projects = tasks.listProjects();
            if (projects.isEmpty())
                throw GenericException.raise("Projects not found", new IllegalArgumentException(expression));
            call(() -> projects.removeIf(p -> !p.getValue().matches(expression)), "Regular expression syntax invalid");
            if (projects.isEmpty())
                throw GenericException.raise("Projects not found", new IllegalArgumentException(expression));
            System.out.printf("Found %d projects matching %s expression\r\n", projects.size(), expression);
        } else {
            projects = new ArrayList<>();
            if (null != projectId) {
                String projectName = tasks.searchProject(projectId);
                if (StringUtils.isNotEmpty(projectName))
                    projects.add(Pair.of(projectId, projectName));
                else
                    throw GenericException.raise("Project not found", new IllegalArgumentException(projectId.toString()));
            } else {
                UUID projectId = tasks.searchProject(projectName);
                if (null != projectId)
                    projects.add(Pair.of(projectId, projectName));
                else
                    throw GenericException.raise("Project not found", new IllegalArgumentException(projectName.toString()));
            }
        }

        DeleteConfirmationStatus status = null == confirmation ? DeleteConfirmationStatus.ALL : DeleteConfirmationStatus.NO;
        for (Pair<UUID, String> project : projects) {
            if (null != confirmation && DeleteConfirmationStatus.ALL != status)
                status = confirmation.confirm(1 == projects.size(), project.getValue(), project.getKey());
            if (DeleteConfirmationStatus.TERMINATE == status) break;
            if (DeleteConfirmationStatus.NO == status) {
                System.out.printf("Project %s skipped\r\n", project.getValue());
                continue;
            }
            tasks.deleteProject(project.getKey());
            System.out.printf("Project %s deleted\r\n", project.getValue());
        }
    }
}
