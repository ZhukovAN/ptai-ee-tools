package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.CliAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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

    @CommandLine.ArgGroup(multiplicity = "1", order = 6)
    private BaseCommand.Reporting reports;

    @CommandLine.Option(
            names = {"--output"}, order = 6,
            paramLabel = "<path>",
            description = "Folder where AST report is to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(Base.DEFAULT_SAST_FOLDER);

    @Override
    public Integer call() throws Exception {
        CliAstJob job = CliAstJob.builder()
                .name(UUID.randomUUID().toString())
                .console(System.out)
                .prefix("")
                .verbose(verbose)
                .insecure(insecure)
                .url(url.toString())
                .token(token)
                .output(output)
                .build();

        try {
            if (null != truststore) {
                String pem = new String(Files.readAllBytes(truststore), StandardCharsets.UTF_8);
                job.setCaCertsPem(pem);
            }
            job.init();

            if (null == projectInfo.id)
                projectInfo.id = job.searchProject(projectInfo.name);
            if (null == projectInfo.id) {
                job.severe("Project " + projectInfo.name + " not found");
                return ExitCode.FAILED.getCode();
            }

            if (null == scanResultId)
                scanResultId = job.latestScanResult(projectInfo.id);
            if (null == scanResultId) {
                job.severe("Latest scan result not found");
                return ExitCode.FAILED.getCode();
            }

            job.generateReports(projectInfo.id, scanResultId, reports.validate(job));
            return ExitCode.SUCCESS.getCode();
        } catch (ApiException e) {
            job.severe(e);
            return ExitCode.FAILED.getCode();
        }
    }
}
