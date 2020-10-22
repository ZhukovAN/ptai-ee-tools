package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.intellij.openapi.diagnostic.Logger;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanError;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanResult;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Stage;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.AstStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.UrlHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import jetbrains.buildServer.RunBuildException;
import jetbrains.buildServer.agent.AgentRunningBuild;
import jetbrains.buildServer.agent.BuildFinishedStatus;
import jetbrains.buildServer.agent.BuildProcess;
import jetbrains.buildServer.agent.BuildRunnerContext;
import jetbrains.buildServer.agent.artifacts.ArtifactsWatcher;
import lombok.extern.java.Log;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.SERVER_SETTINGS_GLOBAL;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.TRUE;

@Log
public class AstBuildProcess implements BuildProcess, Callable<BuildFinishedStatus> {
    private static Logger LOG = Logger.getInstance(AstBuildProcess.class.getName());

    private Future<BuildFinishedStatus> future;

    private final BuildRunnerContext buildRunnerContext;
    private final AgentRunningBuild agentRunningBuild;
    private final ArtifactsWatcher artifactsWatcher;

    private Project project = null;
    private UUID scanResultId = null;

    public AstBuildProcess(AgentRunningBuild agentRunningBuild, BuildRunnerContext buildRunnerContext, ArtifactsWatcher artifactsWatcher) {
        this.agentRunningBuild = agentRunningBuild;
        this.buildRunnerContext = buildRunnerContext;
        this.artifactsWatcher = artifactsWatcher;
        // logger = new AstLoggerAdapter(agentRunningBuild.getBuildLogger());
    }

    // TODO: Get rid of AstStatus / ExitCode etc.
    @Override
    public BuildFinishedStatus call() throws Exception {
        AstStatus status = ast();
        if (AstStatus.ABORTED.equals(status)) {
            log.severe(status.getDescription());
            return BuildFinishedStatus.INTERRUPTED;
        } else if (AstStatus.ERROR.equals(status)) {
            log.severe(status.getDescription());
            return BuildFinishedStatus.FINISHED_FAILED;
        } else if (AstStatus.FAILURE.equals(status)) {
            log.severe(status.getDescription());
            return BuildFinishedStatus.FINISHED_FAILED;
        } else if (AstStatus.SUCCESS.equals(status)) {
            log.info(status.getDescription());
            return BuildFinishedStatus.FINISHED_SUCCESS;
        } else if (AstStatus.UNSTABLE.equals(status)) {
            Map<String, String> params = buildRunnerContext.getRunnerParameters();
            if (TRUE.equalsIgnoreCase(params.get(Params.FAIL_IF_UNSTABLE))) {
                log.severe(status.getDescription());
                return BuildFinishedStatus.FINISHED_FAILED;
            } else {
                log.warning(status.getDescription());
                return BuildFinishedStatus.FINISHED_SUCCESS;
            }
        } else {
            log.severe(status.getDescription());
            return BuildFinishedStatus.FINISHED_FAILED;
        }
    }

    protected String validateNotEmpty(final String value) {
        if (StringUtils.isNotEmpty(value)) return value;
        throw new IllegalArgumentException(Messages.validator_check_field_empty());
    }

    protected String validateUrl(final String value) {
        String url = validateNotEmpty(value);
        if (UrlHelper.checkUrl(url)) return url;
        throw new IllegalArgumentException(Messages.validator_check_url_invalid());
    }

    private AstStatus ast() throws Exception {
        Map<String, String> params = buildRunnerContext.getRunnerParameters();
        Map<String, String> globals = agentRunningBuild.getSharedConfigParameters();

        boolean globalSettingsUsed = SERVER_SETTINGS_GLOBAL.equalsIgnoreCase(params.get(Params.SERVER_SETTINGS));
        if (!globalSettingsUsed) globals = params;

        AstStatus res;
        ScanSettings jsonSettings = null;
        Policy[] jsonPolicy = null;

        if (Constants.AST_SETTINGS_JSON.equalsIgnoreCase(params.get(Params.AST_SETTINGS))) {
            jsonSettings = JsonSettingsHelper.verify(params.get(Params.JSON_SETTINGS));
            if (StringUtils.isNotEmpty(params.get(Params.JSON_POLICY)))
                jsonPolicy = JsonPolicyHelper.verify(params.get(Params.JSON_POLICY));
        }

        String projectName = null == jsonSettings ? validateNotEmpty(params.get(Params.PROJECT_NAME)) : jsonSettings.getProjectName();

        project = new Project(projectName) {
            @Override
            protected void out(final String value) {
                if (null == value) return;
                agentRunningBuild.getBuildLogger().message(value);
            }
            @Override
            protected void out(final Throwable t) {
                if (null == t) return;
                agentRunningBuild.getBuildLogger().exception(t);
            }
        };
        // TODO: Implement JUL custom handler to send generic-client-lib events to TeamCity logger (see https://www.logicbig.com/tutorials/core-java-tutorial/logging/custom-handler.html)

        // No need to set console log and prefix as we override out methods
        project.setVerbose(TRUE.equalsIgnoreCase(params.get(Params.VERBOSE)));

        try {
            project.setUrl(validateUrl(globals.get(Params.URL)));
            project.setToken(validateNotEmpty(globals.get(Params.TOKEN)));
            if (StringUtils.isNotEmpty(globals.get(Params.CERTIFICATES)))
                project.setCaCertsPem(globals.get(Params.CERTIFICATES));
            project.init();

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

            Transfer transfer = new Transfer();
            if (StringUtils.isNotEmpty(params.get(Params.INCLUDES)))
                transfer.setIncludes(params.get(Params.INCLUDES));
            if (StringUtils.isNotEmpty(params.get(Params.EXCLUDES)))
                transfer.setExcludes(params.get(Params.EXCLUDES));
            if (StringUtils.isNotEmpty(params.get(Params.PATTERN_SEPARATOR)))
                transfer.setPatternSeparator(params.get(Params.PATTERN_SEPARATOR));
            if (StringUtils.isNotEmpty(params.get(Params.REMOVE_PREFIX)))
                transfer.setRemovePrefix(params.get(Params.REMOVE_PREFIX));
            transfer.setFlatten(TRUE.equalsIgnoreCase(params.get(Params.FLATTEN)));
            transfer.setUseDefaultExcludes(TRUE.equalsIgnoreCase(params.get(Params.USE_DEFAULT_EXCLUDES)));

            File zip = agentRunningBuild.getBuildTempDirectory().toPath()
                    .resolve(agentRunningBuild.getProjectName())
                    .resolve(agentRunningBuild.getBuildTypeName())
                    .resolve(agentRunningBuild.getBuildNumber() + ".zip").toFile();
            FileCollector.collect(new Transfers().addTransfer(transfer), agentRunningBuild.getCheckoutDirectory(), zip, project);

            project.setSources(zip);
            project.upload();

            String node = params.get(Params.NODE_NAME);
            scanResultId = project.scan(node);
            project.info("PT AI AST result ID is " + scanResultId);

            // TODO: Implement save scan result URL for future use

            boolean failed = false;
            boolean unstable = false;
            String reason;

            ScanResult state = project.waitForComplete(scanResultId);
            Stage stage = state.getProgress().getStage();

            LOG.debug("Resulting stage is " + stage);
            LOG.debug("Resulting statistics is " + state.getStatistic());

            // Generate reports
            if (Stage.DONE.equals(stage) || Stage.ABORTED.equals(stage)) {
                /*
            // Save results to temp folder and tell agent to publish them
            Path out = agentRunningBuild.getBuildTempDirectory().toPath()
                    .resolve(agentRunningBuild.getProjectName())
                    .resolve(agentRunningBuild.getBuildTypeName());
            List<String> results = project.getSastApi().getJobResults(scanId);
            if ((null != results) && (!results.isEmpty())) {
                logger.info("AST results will be stored to {}", out);
                if (!out.toFile().exists())
                    Files.createDirectories(out);
            }
            for (String result : results) {
                File data = project.getSastApi().getJobResult(scanId, result);
                String fileName = out.resolve(result.replaceAll("REPORTS/", "")).toString();
                if (result.endsWith("status.code")) {
                    res = Integer.parseInt(FileUtils.readFileToString(data, StandardCharsets.UTF_8.name()));
                    if (ExitCode.CODES.containsKey(res))
                        logger.info("Status code {}: {}", res, ExitCode.CODES.get(res));
                    Files.write(Paths.get(fileName), res.toString().getBytes());
                } else
                    Files.copy(data.toPath(), Paths.get(fileName), StandardCopyOption.REPLACE_EXISTING);
                artifactsWatcher.addNewArtifactsPath(fileName + "=>" + Base.DEFAULT_SAST_FOLDER);
            }
                 */

            }
            res = AstStatus.convert(state, project.getScanErrors(projectId, scanResultId));

            project.info(res.getDescription());
        } catch (ApiException e) {
            project.severe(Messages.plugin_result_ast_error(e.getMessage()), e);
            res = AstStatus.ERROR;
        } catch (Exception e) {
            // TODO: check catch / ApiException.raise sequences for log redundancy
            log.severe("Exception thrown: " + e.getMessage());
            throw ApiException.raise("Scan error", e);
        }
        return res;
    }

    @Override
    public void start() throws RunBuildException {
        try {
            future = Executors.newSingleThreadExecutor().submit(this);
        } catch (final RejectedExecutionException e) {
            throw new RunBuildException(e);
        }
    }

    @Override
    public boolean isInterrupted() {
        return future.isCancelled() && isFinished();
    }

    @Override
    public boolean isFinished() {
        return future.isDone();
    }

    @Override
    public void interrupt() {
        if ((null != project) && (null != scanResultId)) {
            try {
                project.stop(scanResultId);
            } catch (ApiException e) {
                log.severe("AST job stop failed" + e.getDetailedMessage());
            }
        }
        future.cancel(true);
    }

    @NotNull
    @Override
    public BuildFinishedStatus waitFor() throws RunBuildException {
        try {
            return future.get();
        } catch (final InterruptedException | ExecutionException e) {
            throw new RunBuildException(e);
        } catch (final CancellationException e) {
            return BuildFinishedStatus.INTERRUPTED;
        }
    }
}
