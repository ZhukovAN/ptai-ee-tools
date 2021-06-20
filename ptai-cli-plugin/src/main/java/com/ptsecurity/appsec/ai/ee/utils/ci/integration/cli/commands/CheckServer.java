package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.Callable;

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
    @Override
    public Integer call() throws Exception {
        Utils utils = Utils.builder()
                .console(System.out)
                .prefix("")
                .verbose(verbose)
                .insecure(insecure)
                .url(url.toString())
                .token(token)
                .build();

        try {
            if (null != truststore) {
                String pem = Base.callApi(
                        () -> new String(Files.readAllBytes(truststore), StandardCharsets.UTF_8),
                        Resources.i18n_ast_settings_server_ca_pem_message_file_read_failed());
                utils.setCaCertsPem(pem);
            }
            utils.init();

            Utils.TestResult result = utils.testConnection();
            // result.stream().forEach(r -> utils.info(r));
            utils.info(result.text());
            return Utils.TestResult.State.ERROR.equals(result.state())
                    ? ExitCode.FAILED.getCode()
                    : ExitCode.SUCCESS.getCode();
        } catch (ApiException e) {
            utils.severe(e);
            return ExitCode.FAILED.getCode();
        }
    }
}
