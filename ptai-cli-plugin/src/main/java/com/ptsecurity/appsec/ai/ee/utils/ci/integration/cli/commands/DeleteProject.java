package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.DeleteProjectJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.fusesource.jansi.Ansi;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.Callable;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob.JobExecutionResult.SUCCESS;
import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@CommandLine.Command(
        name = "delete-project",
        sortOptions = false,
        description = "Delete one or more PT AI project",
        exitCodeOnInvalidInput = Plugin.INVALID_INPUT,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"})
public class DeleteProject extends BaseCommand implements Callable<Integer> {
    public static class Project {
        @CommandLine.Option(
                names = {"--project-name"}, required = true, order = 6,
                paramLabel = "<name>",
                description = "PT AI project name")
        protected String projectName;

        @CommandLine.Option(
                names = {"--project-id"}, required = true, order = 6,
                paramLabel = "<id>",
                description = "PT AI project ID")
        protected UUID projectId;

        @CommandLine.Option(
                names = {"--project-name-regexp"}, required = true, order = 6,
                paramLabel = "<expression>",
                description = "Regular expression that used to search for PT AI project name")
        protected String regexp;
    }

    @CommandLine.ArgGroup
    protected Project project;

    @CommandLine.Option(
            names = {"-y", "--yes", "--assume-yes"}, order = 98,
            description = "Automatic yes to prompts; assume \"yes\" as answer to all prompts and run non-interactively")
    protected boolean yes = false;

    @Slf4j
    @SuperBuilder
    public static class CliDeleteProjectJob extends DeleteProjectJob {
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
            super.init();
        }
    }

    protected final Scanner scanner = new Scanner(System.in);

    protected DeleteProjectJob.DeleteConfirmationStatus confirm(final boolean singleProject, @NonNull final String name, @NonNull final UUID id) {
        String answers = singleProject ? "y/N" : "y/N/a";
        System.out.print(
                Ansi.ansi()
                        .a("Are you sure you want to delete PT AI project ")
                        .fg(Ansi.Color.CYAN)
                        .a(name)
                        .reset()
                        .a(" (id: ")
                        .fg(Ansi.Color.CYAN)
                        .a(id)
                        .reset()
                        .a(") [" + answers + "]?")
        );
        try {
            String res = scanner.nextLine();
            if (null == res) res = "";
            return res.trim().equalsIgnoreCase("y")
                    ? DeleteProjectJob.DeleteConfirmationStatus.YES
                    : res.trim().equalsIgnoreCase("a")
                    ? DeleteProjectJob.DeleteConfirmationStatus.ALL
                    : DeleteProjectJob.DeleteConfirmationStatus.NO;
        } catch (NoSuchElementException e) {
            return DeleteProjectJob.DeleteConfirmationStatus.TERMINATE;
        }
    }

    @Override
    public Integer call() {
        CliDeleteProjectJob job = CliDeleteProjectJob.builder()
                .console(System.out)
                .prefix("")
                .verbose(verbose)
                .connectionSettings(ConnectionSettings.builder()
                        .insecure(insecure)
                        .url(url.toString())
                        .credentials(credentials.getBaseCredentials())
                        .build())
                .truststore(truststore)
                .projectId(project.projectId)
                .projectName(project.projectName)
                .expression(project.regexp)
                .confirmation(yes ? null : this::confirm)
                .build();
        AbstractJob.JobExecutionResult res = job.execute();
        scanner.close();

        return SUCCESS == res ? ExitCode.SUCCESS.getCode() : ExitCode.FAILED.getCode();
    }
}
