package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.aic.ExitCode;
import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils.GracefulShutdown;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.Builder;
import lombok.Setter;
import lombok.extern.java.Log;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.UUID;

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

    public Integer execute() {
        Project project = null;
        UUID scanResultId = null;
        ExitCode res = ExitCode.CODE_UNKNOWN_ERROR;

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

            UUID projectId = project.searchProject();
            if (null == projectId) {
                if (null != jsonSettings) {
                    project.info("Project %s not found, will be created as JSON settings are defined", projectName);
                    projectId = project.setupFromJson(jsonSettings, jsonPolicy);
                } else {
                    project.info("Project %s not found", projectName);
                    return ExitCode.CODE_ERROR_PROJECT_NOT_FOUND.getCode();
                }
            } else if (null != jsonSettings)
                project.setupFromJson(jsonSettings, jsonPolicy);

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
                return ExitCode.CODE_SUCCESS.getCode();

            boolean failed = false;
            boolean unstable = false;

            Stage stage = null;
            ScanProgress previousProgress = null;
            ScanResultStatistic previousStatistic = null;

            do {
                Thread.sleep(5000);
                ScanResult state = project.poll(projectId, scanResultId);
                ScanProgress progress = state.getProgress();
                ScanResultStatistic statistic = state.getStatistic();
                boolean somethingChanged = false;
                if (null != progress && !progress.equals(previousProgress)) {
                    String progressInfo = "AST stage: " + progress.getStage() + ", percentage: " + progress.getValue();
                    project.info(progressInfo);
                    previousProgress = progress;
                    somethingChanged = true;
                };
                if (null != statistic && !statistic.equals(previousStatistic)) {
                    project.info("Scan duration: %s", statistic.getScanDuration());
                    if (0 != statistic.getTotalFileCount())
                        project.info("Scanned files: %d out of %d", statistic.getScannedFileCount(), statistic.getTotalFileCount());
                    previousStatistic = statistic;
                    somethingChanged = true;
                };
                if (!somethingChanged)
                    project.fine("Scan status polling done, no change detected");
                if (null != progress) stage = progress.getStage();
            } while (!Stage.DONE.equals(stage) && !Stage.ABORTED.equals(stage) && !Stage.FAILED.equals(stage));

            shutdown.setStopped(true);

            log.finer("Resulting stage is " + stage);
            log.finer("Resulting statistics is " + previousStatistic);

            // Step is failed if scan aborted or failed (i.e. because of license problems)
            failed |= !Stage.DONE.equals(stage);
            if (Stage.ABORTED.equals(stage))
                res = ExitCode.CODE_ERROR_TERMINATED;
            else if (Stage.FAILED.equals(stage))
                res = ExitCode.CODE_UNKNOWN_ERROR;
            else
                res = ExitCode.CODE_ERROR_TERMINATED;

            // Step also failed if policy assessment fails
            // TODO: Swap REJECTED/CONFIRMED states
            //  when https://jira.ptsecurity.com/browse/AI-4866 will be fixed
            if (!failed) {
                failed |= PolicyState.CONFIRMED.equals(previousStatistic.getPolicyState());
                // If scan is done, than the only reason to fail is policy violation
                if (failed)
                    res = ExitCode.CODE_FAILED;
                else if (PolicyState.REJECTED.equals(previousStatistic.getPolicyState()))
                    res = ExitCode.CODE_SUCCESS;
                else
                    res = ExitCode.CODE_POLICY_NOT_DEFINED;
            }

            if (Stage.DONE.equals(stage) || Stage.ABORTED.equals(stage)) {
                // Save reports if scan was started ever
                File json = project.getJsonResult(projectId, scanResultId);
                Files.move(json.toPath(), output.resolve("issues.json"), StandardCopyOption.REPLACE_EXISTING);
            }

            project.info(res.getDescription());
        } catch (Exception e) {
            project.severe(ExitCode.CODE_UNKNOWN_ERROR.getDescription(), e);
        }
        return res.getCode();
    }
}
