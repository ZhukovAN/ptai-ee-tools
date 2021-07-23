package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.ListReportTemplatesJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob.JobExecutionResult.SUCCESS;
import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@CommandLine.Command(
        name = "list-report-templates",
        sortOptions = false,
        description = "Lists available PT AI report templates",
        exitCodeOnInvalidInput = Plugin.INVALID_INPUT,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"})
public class ListReportTemplates extends BaseCommand implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--locale"}, required = true, order = 4,
            paramLabel = "<locale>",
            description = "Locale ID of templates to be listed, one of EN, RU")
    protected Reports.Locale locale;

    @Slf4j
    @SuperBuilder
    public static class CliListReportTeplatesJob extends ListReportTemplatesJob {
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

    @Override
    public Integer call() {
        CliListReportTeplatesJob job = CliListReportTeplatesJob.builder()
                .console(System.out)
                .prefix("")
                .verbose(verbose)
                .connectionSettings(ConnectionSettings.builder()
                        .insecure(insecure)
                        .url(url.toString())
                        .token(token)
                        .build())
                .truststore(truststore)
                .locale(locale)
                .build();
        AbstractJob.JobExecutionResult res = job.execute();
        if (SUCCESS == res) {
            List<String> templateNames = job.getReportTemplates();
            for (String template : templateNames)
                job.info(template);
            return BaseCommand.ExitCode.SUCCESS.getCode();
        } else
            return BaseCommand.ExitCode.FAILED.getCode();
    }
}
