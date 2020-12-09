package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import lombok.extern.java.Log;
import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.Callable;

@Log
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
                String pem = new String(Files.readAllBytes(truststore), StandardCharsets.UTF_8);
                utils.setCaCertsPem(pem);
            }
            utils.init();

            boolean error = false;
            String buildInfoText = "";
            HealthCheck healthCheck = utils.healthCheck();
            if (null == healthCheck || null == healthCheck.getServices()) {
                buildInfoText += "Server returned empty components health data";
                error = true;
            } else {
                long total = healthCheck.getServices().size();
                long healthy = healthCheck.getServices().stream()
                        .filter(s -> "Healthy".equalsIgnoreCase(s.getStatus()))
                        .count();
                buildInfoText += String.format("Healthy services: %d out of %d", healthy, total);
            }
            buildInfoText += ", ";
            EnterpriseLicenseData licenseData = utils.getLicenseData();
            if (null == licenseData) {
                buildInfoText += "Server returned empty license data";
                error = true;
            } else
                buildInfoText += String.format("License: %s, vaildity period: from %s to %s",
                        licenseData.getLicenseNumber(),
                        licenseData.getStartDate(), licenseData.getEndDate());

            utils.info(buildInfoText);
            return error
                    ? ExitCode.FAILED.getCode()
                    : ExitCode.SUCCESS.getCode();
        } catch (ApiException e) {
            utils.severe(e);
            return ExitCode.FAILED.getCode();
        }
    }
}
