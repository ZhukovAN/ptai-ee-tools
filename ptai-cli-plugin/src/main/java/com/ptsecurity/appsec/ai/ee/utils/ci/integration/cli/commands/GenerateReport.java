package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations.LocalFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenerateReportsJob;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.concurrent.Callable;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob.JobExecutionResult.SUCCESS;
import static java.nio.charset.StandardCharsets.UTF_8;

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
    protected ProjectInfo projectInfo = null;

    @CommandLine.Option(
            names = {"--scan-result-id"}, order = 5,
            paramLabel = "<UUID>",
            description = "PT AI project scan result ID. If no value is defined latest scan result will be used for report generation")
    protected UUID scanResultId = null;

    /**
     * Reports to be generated. As multiplicity equals 1 this parameter is required,
     * so at least one report is to be defined
     */
    @CommandLine.ArgGroup(multiplicity = "1", order = 6)
    protected BaseCommand.Reporting reports = null;

    @CommandLine.Option(
            names = {"--output"}, order = 6,
            paramLabel = "<path>",
            description = "Folder where AST report is to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(AbstractJob.DEFAULT_OUTPUT_FOLDER);

    @Slf4j
    @SuperBuilder
    public static class CliGenerateReportsJob extends GenerateReportsJob {
        protected Path truststore;
        @Override
        protected void init() throws GenericException {
            String caCertsPem = (null == truststore)
                    ? null
                    : CallHelper.call(
                    () -> {
                        log.debug("Loading trusted certificates from {}", truststore.toString());
                        return new String(Files.readAllBytes(truststore), UTF_8);
                    },
                    Resources.i18n_ast_settings_server_ca_pem_message_file_read_failed());
            connectionSettings.setCaCertsPem(caCertsPem);
            fileOps = LocalFileOperations.builder()
                    .console(this)
                    .saver(this)
                    .build();
            super.init();
        }
    }

    /**
     * Generate reports defined by CLI parameters
     * @return Reports generation exit code
     */
    @Override
    public Integer call() {
        CliGenerateReportsJob job = CliGenerateReportsJob.builder()
                .console(System.out).prefix("").verbose(verbose)
                .connectionSettings(ConnectionSettings.builder()
                        .url(url.toString())
                        .credentials(credentials.getBaseCredentials())
                        .insecure(insecure)
                        .build())
                .projectId(projectInfo.id)
                .projectName(projectInfo.name)
                .scanResultId(scanResultId)
                .output(output)
                .reports(reports.convert())
                .truststore(truststore)
                .build();
        return (SUCCESS == job.execute())
                ? BaseCommand.ExitCode.SUCCESS.getCode()
                : BaseCommand.ExitCode.FAILED.getCode();
    }
}
