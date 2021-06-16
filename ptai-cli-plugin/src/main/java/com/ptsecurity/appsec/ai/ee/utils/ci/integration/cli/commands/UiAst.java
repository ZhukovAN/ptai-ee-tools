package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.scanscheduler.model.ScanType;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.CliAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob.JobFinishedStatus.SUCCESS;

@Slf4j
@CommandLine.Command(
        name = "ui-ast",
        sortOptions = false,
        description = "Calls PT AI for AST. Project settings are defined in the PT AI viewer UI",
        exitCodeOnInvalidInput = Plugin.INVALID_INPUT,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"})
public class UiAst extends BaseCommand implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--input"}, order = 3,
            required = true,
            paramLabel = "<path>",
            description = "Source file or folder to scan")
    protected Path input = Paths.get(System.getProperty("user.dir"));

    @CommandLine.Option(
            names = {"--output"}, order = 4,
            paramLabel = "<path>",
            description = "Folder where AST reports are to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(Base.DEFAULT_SAST_FOLDER);

    @CommandLine.Option(
            names = {"-p", "--project"}, order = 5,
            required = true,
            paramLabel = "<name>",
            description = "Project name how it is setup and seen in the PT AI viewer")
    protected String project = null;

    @CommandLine.Option(
            names = {"-i", "--includes"}, order = 6,
            paramLabel = "<pattern>",
            description = "Comma-separated list of files to include to scan. The string is a comma separated list of includes for an Ant fileset eg. '**/*.jar'" +
                    "(see http://ant.apache.org/manual/dirtasks.html#patterns). The base directory for this fileset is the sources folder")
    private String includes = null;

    @CommandLine.Option(
            names = {"-e", "--excludes"}, order = 7,
            paramLabel = "<pattern>",
            description = "Comma-separated list of files to exclude from scan. The syntax is the same as for includes")
    private String excludes = null;

    @CommandLine.Option(
            names = {"--use-default-excludes"}, order = 8,
            description = "Use default excludes list")
    private boolean useDefaultExcludes = false;

    @CommandLine.ArgGroup(exclusive = true)
    BaseCommand.Reporting reports;

    @CommandLine.Option(
            names = {"--fail-if-failed"}, order = 10,
            description = "Return code failed if AST failed")
    private boolean failIfFailed = false;

    @CommandLine.Option(
            names = {"--fail-if-unstable"}, order = 11,
            description = "Return code failed if AST unstable")
    private boolean failIfUnstable = false;

    @CommandLine.Option(
            names = {"--async"}, order = 20,
            description = "Do not wait AST to complete and exit immediately")
    private boolean async = false;

    @CommandLine.Option(
            names = {"--full-scan"}, order = 21,
            description = "Execute full AST instead of incremental")
    private boolean fullScan = false;

    @Override
    public Integer call() throws Exception {
        CliAstJob job = CliAstJob.builder()
                .console(System.out).prefix("").verbose(verbose)
                .url(url.toString()).token(token).insecure(insecure)
                .name(project)
                .async(async)
                .failIfFailed(failIfFailed).failIfUnstable(failIfUnstable)
                .input(input).output(output)
                .includes(includes).excludes(excludes)
                .useDefaultExcludes(useDefaultExcludes)
                .reporting(reports)
                .truststore(truststore)
                .fullScanMode(fullScan)
                .build();
        if (!job.init()) return BaseCommand.ExitCode.FAILED.getCode();
        return (SUCCESS == job.execute())
                ? BaseCommand.ExitCode.SUCCESS.getCode()
                : BaseCommand.ExitCode.FAILED.getCode();
    }
}
