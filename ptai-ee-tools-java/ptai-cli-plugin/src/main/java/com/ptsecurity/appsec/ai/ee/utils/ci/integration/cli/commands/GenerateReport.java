package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.CliAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.concurrent.Callable;

@Slf4j
@CommandLine.Command(
        name = "generate-report",
        sortOptions = false,
        description = "Generates PT AI report based on AST results",
        exitCodeOnInvalidInput = Plugin.INVALID_INPUT,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"})
public class GenerateReport extends BaseCommand implements Callable<Integer> {
    static class ProjectInfo {
        @CommandLine.Option(
                names = {"--project-name"}, order = 4, required = true,
                paramLabel = "<name>",
                description = "PT AI project name")
        protected String name;

        @CommandLine.Option(
                names = {"--project-id"}, order = 4, required = true,
                paramLabel = "<UUID>",
                description = "PT AI project Id")
        UUID id;
    }

    @CommandLine.ArgGroup(multiplicity = "1")
    private ProjectInfo projectInfo;

    @CommandLine.Option(
            names = {"--scan-result-id"}, order = 5,
            paramLabel = "<UUID>",
            description = "PT AI project scan result ID. If no value is defined latest scan result will be used for report generation")
    private UUID scanResultId;

    /**
     * Reports to be generated. As multiplicity equals 1 this parameter is required,
     * so at least one report is to be defined
     */
    @CommandLine.ArgGroup(multiplicity = "1", order = 6, exclusive = true)
    private BaseCommand.Reporting reports;

    @CommandLine.Option(
            names = {"--output"}, order = 6,
            paramLabel = "<path>",
            description = "Folder where AST report is to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(Base.DEFAULT_SAST_FOLDER);

    /**
     * Generate reports defined by CLI parameters. As report generation
     * does not start AST process, this method creates dummy AST job with
     * random name and cals its
     * {@link com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob#generateReports(UUID, UUID, Reports)}
     * report generation method
     * @return Reports generation exit code
     * @throws Exception
     */
    @Override
    public Integer call() throws Exception {
        // Create dummy AST job that will be used for reports generation
        CliAstJob job = CliAstJob.builder()
                .console(System.out).prefix("").verbose(verbose)
                .url(url.toString()).token(token).insecure(insecure)
                .output(output)
                .truststore(truststore)
                .build();

        try {
            if (!job.init())
                return ExitCode.FAILED.getCode();

            if (null == projectInfo.id)
                projectInfo.id = job.searchProject(projectInfo.name);
            if (null == projectInfo.id)
                throw ApiException.raise("Project " + projectInfo.name + " not found", new IllegalArgumentException(projectInfo.name));

            if (null == scanResultId)
                scanResultId = job.latestScanResult(projectInfo.id);
            if (null == scanResultId)
                throw ApiException.raise("Latest scan result not found", new IllegalArgumentException(projectInfo.name));

            job.generateReports(projectInfo.id, scanResultId, reports.convert());
            return ExitCode.SUCCESS.getCode();
        } catch (ApiException e) {
            job.severe(e);
            return ExitCode.FAILED.getCode();
        }
    }
}
