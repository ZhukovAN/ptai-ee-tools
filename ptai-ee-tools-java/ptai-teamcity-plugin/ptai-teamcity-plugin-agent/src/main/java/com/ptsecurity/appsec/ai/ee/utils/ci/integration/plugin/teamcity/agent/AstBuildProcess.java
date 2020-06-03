package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.aic.ExitCode;
import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicyVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import jetbrains.buildServer.RunBuildException;
import jetbrains.buildServer.agent.AgentRunningBuild;
import jetbrains.buildServer.agent.BuildFinishedStatus;
import jetbrains.buildServer.agent.BuildProcess;
import jetbrains.buildServer.agent.BuildRunnerContext;
import jetbrains.buildServer.agent.artifacts.ArtifactsWatcher;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.TRUE;

public class AstBuildProcess implements BuildProcess, Callable<BuildFinishedStatus> {

    private Future<BuildFinishedStatus> future;

    private final BuildRunnerContext buildRunnerContext;
    private final AgentRunningBuild agentRunningBuild;
    private final ArtifactsWatcher artifactsWatcher;
    private final AstLoggerAdapter logger;

    Client client = null;
    Integer scanId = null;

    public AstBuildProcess(AgentRunningBuild agentRunningBuild, BuildRunnerContext buildRunnerContext, ArtifactsWatcher artifactsWatcher) {
        this.agentRunningBuild = agentRunningBuild;
        this.buildRunnerContext = buildRunnerContext;
        this.artifactsWatcher = artifactsWatcher;
        logger = new AstLoggerAdapter(agentRunningBuild.getBuildLogger());
    }

    @Override
    public BuildFinishedStatus call() throws Exception {
        Integer res = ast();
        PtaiResultStatus status = PtaiResultStatus.convert(res);
        if (PtaiResultStatus.ABORTED.equals(status))
            return BuildFinishedStatus.INTERRUPTED;
        else if (PtaiResultStatus.ERROR.equals(status))
            return BuildFinishedStatus.FINISHED_FAILED;
        else if (PtaiResultStatus.FAILURE.equals(status))
            return BuildFinishedStatus.FINISHED_FAILED;
        else if (PtaiResultStatus.SUCCESS.equals(status))
            return BuildFinishedStatus.FINISHED_SUCCESS;
        else if (PtaiResultStatus.UNSTABLE.equals(status))
            return BuildFinishedStatus.FINISHED_WITH_PROBLEMS;
        else
            return BuildFinishedStatus.FINISHED_FAILED;
    }

    protected String validateNotEmpty(final String value) {
        if (StringUtils.isNotEmpty(value)) return value;
        throw new BaseClientException("Empty value is not allowed");
    }

    private static final UrlValidator urlValidator = new UrlValidator(new String[] {"http","https"}, UrlValidator.ALLOW_LOCAL_URLS);

    protected String validateUrl(final String value) {
        String url = validateNotEmpty(value);
        if (urlValidator.isValid(url)) return url;
        throw new BaseClientException("Invalid URL");
    }

    protected Integer ast() throws Exception {
        Map<String, String> params = buildRunnerContext.getRunnerParameters();
        Map<String, String> globals = agentRunningBuild.getSharedConfigParameters();

        Integer res = ExitCode.CODE_UNKNOWN_ERROR.getCode();
        try {
            client = new Client();
            client.setUrl(validateUrl(globals.get(Params.GLOBAL_URL)));
            client.setClientId(Constants.CLIENT_ID);
            client.setClientSecret(Constants.CLIENT_SECRET);
            // client.setConsoleLog(this.consoleLog);
            client.setVerbose(TRUE.equalsIgnoreCase(params.get(Params.VERBOSE)));
            // client.setLogPrefix(this.logPrefix);

            if (StringUtils.isNotEmpty(globals.get(Params.GLOBAL_TRUSTED_CERTIFICATES)))
                client.setCaCertsPem(globals.get(Params.GLOBAL_TRUSTED_CERTIFICATES));

            client.setUserName(validateNotEmpty(globals.get(Params.GLOBAL_USER)));
            client.setPassword(validateNotEmpty(globals.get(Params.GLOBAL_TOKEN)));
            client.init();

            ScanSettings jsonSettings = null;
            Policy[] jsonPolicy = null;

            if (Constants.SETTINGS_JSON.equalsIgnoreCase(params.get(Params.SCAN_SETTINGS))) {
                jsonSettings = JsonSettingsVerifier.verify(params.get(Params.JSON_SETTINGS));
                if (StringUtils.isNotEmpty(params.get(Params.JSON_POLICY)))
                    jsonPolicy = JsonPolicyVerifier.verify(params.get(Params.JSON_POLICY));
            }

            String projectName = null == jsonSettings ? validateNotEmpty(params.get(Params.PROJECT_NAME)) : jsonSettings.getProjectName();

            try {
                client.getDiagnosticApi().getProjectId(projectName);
            } catch (ApiException e) {
                if (HttpStatus.SC_NOT_FOUND == e.getCode()) {
                    // Project not found - create it if AST parameters are defined
                    if (null != jsonSettings) {
                        logger.info("Project {} not found, will be created as JSON settings are defined", projectName);
                        client.getSastApi().createProject(projectName);
                    } else {
                        logger.error("Project {} not found", projectName);
                        return ExitCode.CODE_ERROR_PROJECT_NOT_FOUND.getCode();
                    }
                } else
                    throw e;
            }
            Transfer transfer = new Transfer();
            if (StringUtils.isNotEmpty(params.get(Params.INCLUDES)))
                transfer.setIncludes(params.get(Params.INCLUDES));
            if (StringUtils.isNotEmpty(params.get(Params.EXCLUDES)))
                transfer.setExcludes(params.get(Params.EXCLUDES));
            Base base = new Base() {
                public void log(String value) {
                    logger.info(value);
                }
            };
            base.setVerbose(TRUE.equalsIgnoreCase(params.get(Params.VERBOSE)));

            File zip = agentRunningBuild.getBuildTempDirectory().toPath()
                    .resolve(agentRunningBuild.getProjectName())
                    .resolve(agentRunningBuild.getBuildTypeName())
                    .resolve(agentRunningBuild.getBuildNumber() + ".zip").toFile();
            FileCollector.collect(new Transfers().addTransfer(transfer), agentRunningBuild.getCheckoutDirectory(), zip, base);
            client.uploadZip(projectName, zip, 1024 * 1024);

            String node = params.get(Params.NODE_NAME);

            if (null == jsonSettings)
                scanId = client.getSastApi().startUiJob(projectName, StringUtils.isEmpty(node) ? Base.DEFAULT_PTAI_NODE_NAME : node);
            else
                scanId = client.getSastApi().startJsonJob(
                        projectName,
                        StringUtils.isEmpty(node) ? Base.DEFAULT_PTAI_NODE_NAME : node,
                        new ObjectMapper().writeValueAsString(jsonSettings.fix()),
                        null == jsonPolicy ? "" : new ObjectMapper().writeValueAsString(jsonPolicy));

            logger.info("SAST job number is {}", scanId);

            JobState state = null;
            int pos = 0;
            do {
                state = client.getSastApi().getScanJobState(scanId, pos);
                if (state.getPos() != pos) {
                    String[] lines = state.getLog().split("\\r?\\n");
                    for (String line : lines)
                        logger.info(line);
                }
                pos = state.getPos();
                if (!state.getStatus().equals(JobState.StatusEnum.UNKNOWN)) break;
                Thread.sleep(2000);
            } while (true);

            // Save results to temp folder and tell agent to publish them
            Path out = agentRunningBuild.getBuildTempDirectory().toPath()
                    .resolve(agentRunningBuild.getProjectName())
                    .resolve(agentRunningBuild.getBuildTypeName());
            List<String> results = client.getSastApi().getJobResults(scanId);
            if ((null != results) && (!results.isEmpty())) {
                logger.info("AST results will be stored to {}", out);
                if (!out.toFile().exists())
                    Files.createDirectories(out);
            }
            for (String result : results) {
                File data = client.getSastApi().getJobResult(scanId, result);
                String fileName = out.resolve(result.replaceAll("REPORTS/", "")).toString();
                if (result.endsWith("status.code")) {
                    res = Integer.parseInt(FileUtils.readFileToString(data, StandardCharsets.UTF_8.name()));
                    if (ExitCode.CODES.containsKey(res))
                        logger.info("Status code {}: {}", res, ExitCode.CODES.get(res));
                    Files.write(Paths.get(fileName), res.toString().getBytes());
                } else
                    Files.copy(data.toPath(), Paths.get(fileName), StandardCopyOption.REPLACE_EXISTING);
                artifactsWatcher.addNewArtifactsPath(fileName + "=>" + Base.SAST_FOLDER);
            }
        } catch (InterruptedException e) {
            logger.error("Interrupted exception: " + e.getMessage());
            if ((null != client) && (null != scanId))
                client.getSastApi().stopScan(scanId);
            throw new RunBuildException(e.getMessage());
        } catch (Exception e) {
            logger.error("Exception thrown: " + e.getMessage(), e);
            throw new RunBuildException(e);
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
        if ((null != client) && (null != scanId)) {
            try {
                client.getSastApi().stopScan(scanId);
            } catch (ApiException e) {
                logger.error("AST job stop failed", e);
            }
        }
        future.cancel(true);
    }

    @NotNull
    @Override
    public BuildFinishedStatus waitFor() throws RunBuildException {
        try {
            final BuildFinishedStatus status = future.get();
            return status;
        } catch (final InterruptedException e) {
            throw new RunBuildException(e);
        } catch (final ExecutionException e) {
            throw new RunBuildException(e);
        } catch (final CancellationException e) {
            return BuildFinishedStatus.INTERRUPTED;
        }
    }
}
