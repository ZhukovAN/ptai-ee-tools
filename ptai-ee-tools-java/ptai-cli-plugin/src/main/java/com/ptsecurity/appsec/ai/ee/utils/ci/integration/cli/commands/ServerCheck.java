package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import lombok.extern.java.Log;
import picocli.CommandLine;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Log
@CommandLine.Command(
        name = "server-check",
        sortOptions = false,
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "2:Warning",
                "1000:Invalid input"},
        description = "Checks PT AI server connection")
public class ServerCheck extends BaseAst implements Callable<Integer> {
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
            description = "Path to PEM file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 4,
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @Override
    public Integer call() throws Exception {
        Utils utils = new Utils();
        utils.setConsole(System.out);
        utils.setPrefix("");
        utils.setVerbose(verbose);

        try {
            utils.setUrl(url.toString());
            utils.setToken(token);
            if (null != truststore) {
                String pem = new String(Files.readAllBytes(truststore), StandardCharsets.UTF_8);
                utils.setCaCertsPem(pem);
            }
            utils.init();

            boolean error = false;
            boolean warning = false;
            String buildInfoText = "";
            HealthCheck healthCheck = utils.healthCheck();
            if (null == healthCheck) {
                buildInfoText += "Server returned empty components health data";
                error = true;
            } else {
                long total = healthCheck.getServices().size();
                long healthy = healthCheck.getServices().stream()
                        .filter(s -> "Healthy".equalsIgnoreCase(s.getStatus()))
                        .count();
                buildInfoText += String.format("Healthy services: %d out of %d", healthy, total);
                if (0 == healthy) warning = true;
            }
            buildInfoText += ", ";
            EnterpriseLicenseData licenseData = utils.getLicenseData();
            if (null == licenseData) {
                buildInfoText += "Server returned empty license data";
                error = true;
            } else {
                buildInfoText += String.format("License: %s, vaildity period: from %s to %s",
                        licenseData.getLicenseNumber(),
                        licenseData.getStartDate(), licenseData.getEndDate());
                if (!licenseData.getIsValid()) warning = true;
            }

            utils.info(buildInfoText);
            return error
                    ? ExitCode.ERROR.getCode()
                    : warning
                    ? ExitCode.WARNINGS.getCode()
                    : ExitCode.SUCCESS.getCode();
        } catch (Exception e) {
            utils.severe("Server check", e);
            return ExitCode.ERROR.getCode();
        }
    }
}
