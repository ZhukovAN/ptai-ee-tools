package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.FileSaver;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.functions.TextOutput;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.FileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.util.UUID;

@Slf4j
@Getter
@SuperBuilder
public class GenerateReportsJob extends AbstractJob implements FileSaver, TextOutput {

    protected String projectName;
    protected UUID projectId;
    protected UUID scanResultId;

    protected Path output;

    /**
     * Set of reports to be generated
     */
    @Setter
    protected Reports reports;

    @Builder.Default
    protected FileOperations fileOps = null;

    @Override
    protected void init() throws GenericException {

    }

    @Override
    protected void unsafeExecute() throws GenericException {
        ReportsTasks reportsTasks = new Factory().reportsTasks(client);
        ProjectTasks projectTasks = new Factory().projectTasks(client);

        if (null == projectId)
            projectId = projectTasks.searchProject(projectName);
        if (null == projectId)
            throw GenericException.raise("Project " + projectName + " not found", new IllegalArgumentException(projectName));

        if (null == scanResultId)
            scanResultId = projectTasks.getLatestAstResult(projectId);
        if (null == scanResultId)
            throw GenericException.raise("Latest scan result not found", new IllegalArgumentException(projectName));

        reportsTasks.exportAdvanced(projectId, scanResultId, reports, fileOps);
    }
}
