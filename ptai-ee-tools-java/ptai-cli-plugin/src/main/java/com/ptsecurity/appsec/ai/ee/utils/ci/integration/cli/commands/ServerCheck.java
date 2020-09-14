package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import lombok.extern.log4j.Log4j2;
import picocli.CommandLine;

import java.net.URL;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Log4j2
@CommandLine.Command(
        name = "server-check",
        sortOptions = false,
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"},
        description = "Checks PT AI server connection")
public class ServerCheck extends BaseSlimAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI server URL, i.e. https://ptai.domain.org:443")
    protected URL url;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true, order = 2,
            paramLabel = "<token>",
            description = "PT AI server API token")
    protected String token = null;

    @CommandLine.Option(
            names = {"--truststore"}, order = 3,
            paramLabel = "<path>",
            description = "Path to file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 4,
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @Override
    public Integer call() throws Exception {
        try {
            Utils utils = new Utils();
            utils.setUrl(url.toString());
            utils.setToken(token);
            if (null != truststore) utils.setCaCertsJks(truststore);
            utils.init();

            EnterpriseLicenseData license = utils.getLicenseData();
            log.info("License number: {}", license.getLicenseNumber());
            // return (statuses.getPtai().equals(FAILURE) || statuses.getEmbedded().equals(FAILURE)) ? 1 : 0;
            return 0;
        } catch (Exception e) {
            processApiException("Server check", e, verbose);
            return 1;
        }
    }
}
