package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportTemplateModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import lombok.extern.java.Log;
import picocli.CommandLine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.Callable;

@Log
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

            List<ReportTemplateModel> templates = utils.getReportTemplates(locale);
            for (ReportTemplateModel template : templates) {
                System.out.println(template.getName());
            }

            return ExitCode.SUCCESS.getCode();
        } catch (ApiException e) {
            utils.severe(e);
            return ExitCode.FAILED.getCode();
        }
    }
}
