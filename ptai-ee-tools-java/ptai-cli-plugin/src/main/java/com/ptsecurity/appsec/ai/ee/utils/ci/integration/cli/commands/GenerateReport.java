package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportFormatType;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportTemplateModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Utils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ReportHelper;
import lombok.extern.java.Log;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import picocli.CommandLine;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

@Log
@CommandLine.Command(
        name = "generate-report",
        sortOptions = false,
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "2:Warning",
                "1000:Invalid input"},
        description = "Generates PT AI report based on AST results")
public class GenerateReport extends BaseAst implements Callable<Integer> {
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
        protected UUID id;
    }

    @CommandLine.ArgGroup(exclusive = true, multiplicity = "1")
    ProjectInfo projectInfo;

    @CommandLine.Option(
            names = {"--scan-result-id"}, order = 5,
            paramLabel = "<UUID>",
            description = "PT AI project scan result ID. If no value is defined latest scan result will be used for report generation")
    protected UUID scanResultId;

    @CommandLine.ArgGroup(exclusive = false, multiplicity = "1", order = 6)
    Report report;

    @CommandLine.Option(
            names = {"--output"}, order = 6,
            paramLabel = "<path>",
            description = "Folder where AST report is to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(Base.DEFAULT_SAST_FOLDER);

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 99,
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

            if (null == projectInfo.id)
                projectInfo.id = utils.searchProject(projectInfo.name);
            if (null == projectInfo.id) {
                utils.severe("Project " + projectInfo.name + " not found");
                return ExitCode.ERROR.getCode();
            }

            if (null == scanResultId)
                scanResultId = utils.latestScanResult(projectInfo.id);
            if (null == scanResultId) {
                utils.severe("Latest scan result not found");
                return ExitCode.ERROR.getCode();
            }

            output.toFile().mkdirs();
            File reportFile = utils.generateReport(
                    projectInfo.id, scanResultId,
                    report.template, report.locale.getValue(),
                    ReportFormatType.fromValue(report.format.getValue()));
            String reportName = ReportHelper.generateReportFileNameTemplate(
                    report.template,
                    report.locale.getValue(),
                    ReportFormatType.fromValue(report.format.getValue()).getValue());
            reportName = ReportHelper.removePlaceholder(reportName);
            FileUtils.moveFile(reportFile, output.resolve(reportName).toFile());
            utils.fine("Report saved as %s", reportName);

            return ExitCode.SUCCESS.getCode();
        } catch (Exception e) {
            utils.severe("Report generation error", e);
            return ExitCode.ERROR.getCode();
        }
    }
}
