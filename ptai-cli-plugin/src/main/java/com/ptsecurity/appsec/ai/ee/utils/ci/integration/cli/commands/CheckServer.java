package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.CheckServerJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob.JobExecutionResult.SUCCESS;
import static java.awt.SystemColor.info;
import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@CommandLine.Command(
        name = "check-server",
        sortOptions = false,
        description = "Checks PT AI server connection",
        exitCodeOnInvalidInput = Plugin.INVALID_INPUT,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"})
public class CheckServer extends BaseCommand implements Callable<Integer> {

    @Slf4j
    @SuperBuilder
    public static class CliCheckServerJob extends CheckServerJob {
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
    public Integer call() throws Exception {
        CliCheckServerJob job = CliCheckServerJob.builder()
                .console(System.out)
                .prefix("")
                .verbose(verbose)
                .connectionSettings(ConnectionSettings.builder()
                        .insecure(insecure)
                        .url(url.toString())
                        .token(token)
                        .build())
                .truststore(truststore)
                .build();
        AbstractJob.JobExecutionResult res = job.execute();
        if (SUCCESS == res) {
            ServerCheckResult serverCheckResult = job.getServerCheckResult();
            job.info(serverCheckResult.text());
            return ExitCode.SUCCESS.getCode();
        } else
            return BaseCommand.ExitCode.FAILED.getCode();
    }
}
