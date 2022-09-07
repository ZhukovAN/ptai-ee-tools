package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.util.UUID;

@Slf4j
@SuperBuilder
public class UiAstJobSetupOperationsImpl extends AbstractSetupOperations implements SetupOperations {
    @Override
    public UUID setupProject() throws GenericException {
        if (StringUtils.isEmpty(owner.getProjectName()))
            throw GenericException.raise("Project setup failed", new IllegalArgumentException("Project name not defined"));
        ProjectTasks projectTasks = new Factory().projectTasks(owner.getClient());
        UUID projectId = projectTasks.searchProject(owner.getProjectName());

        if (null == projectId) {
            owner.info("Project %s not found", owner.getProjectName());
            throw GenericException.raise("Project setup failed", new IllegalArgumentException("Project " + owner.getProjectName() + " not found"));
        }

        uploadSources(projectId);
        return projectId;
    }
}
