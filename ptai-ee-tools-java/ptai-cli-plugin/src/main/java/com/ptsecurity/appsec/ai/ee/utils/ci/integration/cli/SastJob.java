package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils.GracefulShutdown;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.AstStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.Builder;
import lombok.Setter;
import lombok.extern.java.Log;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseCommand.*;

@Log
@Setter
@Builder
public class SastJob extends Base {
    protected final URL url;
    protected final String projectName;
    protected ScanSettings jsonSettings;
    protected Policy[] jsonPolicy;

    protected String serverCaCertificates;

    protected final Path input;
    protected String includes;
    protected String excludes;
    protected final String node;
    protected final String token;
    protected final Path output;

    protected final boolean async;

    protected Report report;

    public AstStatus execute() {
        Project project = null;
        UUID scanResultId = null;
        AstStatus res = AstStatus.UNKNOWN;
        try {
            String projectName = null == jsonSettings ? this.projectName : jsonSettings.getProjectName();

            project = new Project(projectName);
            project.setConsole(this.console);
            project.setVerbose(verbose);
            project.setPrefix(this.prefix);

            project.setUrl(url.toString());
            project.setToken(token);
            if (StringUtils.isNotEmpty(serverCaCertificates))
                project.setCaCertsPem(serverCaCertificates);
            project.init();

            List<NamedReportDefinition> reportDefinitions = null;
            if (null != report)
                reportDefinitions = report.validate(project);

            UUID projectId = project.searchProject();
            if (null == projectId) {
                if (null != jsonSettings) {
                    project.info("Project %s not found, will be created as JSON settings are defined", projectName);
                    projectId = project.setupFromJson(jsonSettings, jsonPolicy);
                } else {
                    project.info("Project %s not found", projectName);
                    return AstStatus.ERROR;
                }
            } else if (null != jsonSettings)
                project.setupFromJson(jsonSettings, jsonPolicy);
            project.info("PT AI project ID is " + projectId);

            Transfer transfer = new Transfer();
            if (StringUtils.isNotEmpty(includes)) transfer.setIncludes(includes);
            if (StringUtils.isNotEmpty(excludes)) transfer.setExcludes(excludes);
            File zip = FileCollector.collect(new Transfers().addTransfer(transfer), input.toFile(), this);
            project.setSources(zip);
            project.upload();

            scanResultId = project.scan(node);
            project.info("PT AI AST result ID is " + scanResultId);
            GracefulShutdown shutdown = new GracefulShutdown(this, project, scanResultId);
            Runtime.getRuntime().addShutdownHook(shutdown);

            output.toFile().mkdirs();

            String url = String.format("%s/api/Projects/%s/scanResults/%s", project.getUrl(), projectId, scanResultId);
            Files.write(output.resolve("result.url"), url.getBytes());
            if (async)
                // Asynchronous mode means that we aren't need to wait AST job
                // completion. Just write scan result access URL and exit
                return AstStatus.SUCCESS;

            boolean failed = false;
            boolean unstable = false;

            ScanResult state = project.waitForComplete(scanResultId);

            Stage stage = state.getProgress().getStage();

            shutdown.setStopped(true);

            project.fine("Resulting stage is " + stage);
            project.fine("Resulting statistics is " + state.getStatistic());

            if (Stage.DONE.equals(stage) || Stage.ABORTED.equals(stage)) {
                // Save reports if scan was started ever
                File json = project.getJsonResult(projectId, scanResultId);
                Files.move(json.toPath(), output.resolve("issues.json"), StandardCopyOption.REPLACE_EXISTING);

                if (null != report) {
                    try {
                        output.toFile().mkdirs();
                        for (NamedReportDefinition reportDefinition : reportDefinitions) {
                            File reportFile = project.generateReport(
                                    projectId, scanResultId,
                                    reportDefinition.getTemplate(), reportDefinition.getLocale().getValue(),
                                    ReportFormatType.fromValue(reportDefinition.getFormat().getValue()));
                            if (output.resolve(reportDefinition.getName()).toFile().exists()) {
                                log.warning("Existing report " + reportDefinition.getName() + " will be overwritten");
                                if (!output.resolve(reportDefinition.getName()).toFile().delete())
                                    log.severe("Report " + reportDefinition.getName() + " delete failed");
                            }
                            FileUtils.moveFile(reportFile, output.resolve(reportDefinition.getName()).toFile());
                            project.fine("Report saved as %s", reportDefinition.getName());

                        }
                    } catch (ApiException e) {
                        project.warning("Report save failed", e);
                        unstable = true;
                    }
                }
            }

            res = AstStatus.convert(state, project.getScanErrors(projectId, scanResultId));

            project.info(res.getDescription());
        } catch (ApiException e) {
            project.severe(e.getMessage(), e.getInner());
            res = AstStatus.ERROR;
        } catch (Exception e) {
            project.severe(Messages.messages_error_generic(), e);
            res = AstStatus.ERROR;
        }
        return res;
    }
}
