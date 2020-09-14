package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.aic.ExitCode;
import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.utils.GracefulShutdown;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.Builder;
import lombok.Setter;
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

@Setter
@Builder
public class SlimSastJob extends Base {
    protected final URL url;
    protected final String project;
    protected ScanSettings jsonSettings;
    protected Policy[] jsonPolicy;

    protected Path truststore;
    protected String truststoreType;
    protected String truststorePassword;

    protected final Path input;
    protected String includes;
    protected String excludes;
    protected final String node;
    protected final String username;
    protected final String token;
    protected final Path output;

    protected final String clientId;
    protected final String clientSecret;

    public Integer execute() {
        Client client = null;
        Integer scanId = null;
        Integer res = ExitCode.CODE_UNKNOWN_ERROR.getCode();
        try {
            client = new Client();
            client.setUrl(url.toString());
            client.setClientId(clientId);
            client.setClientSecret(clientSecret);
            client.setConsole(this.console);
            client.setVerbose(verbose);
            client.setLogPrefix(this.logPrefix);

            if (null != truststore) {
                client.setTrustStoreFile(truststore.toString());
                client.setTrustStoreType(truststoreType);
                client.setTrustStorePassword(truststorePassword);
            }

            client.setUserName(username);
            client.setPassword(token);
            client.init();

            String projectName = null == jsonSettings ? project : jsonSettings.getProjectName();

            try {
                client.getDiagnosticApi().getProjectId(projectName);
            } catch (ApiException e) {
                if (HttpStatus.SC_NOT_FOUND == e.getCode()) {
                    // Project not found - create it if AST parameters are defined
                    if (null != jsonSettings) {
                        log("Project %s not found, will be created as JSON settings are defined", projectName);
                        client.getSastApi().createProject(projectName);
                    } else {
                        log("Project %s not found", projectName);
                        return ExitCode.CODE_ERROR_PROJECT_NOT_FOUND.getCode();
                    }
                } else
                    throw e;
            }
            Transfer transfer = new Transfer();
            if (StringUtils.isNotEmpty(includes)) transfer.setIncludes(includes);
            if (StringUtils.isNotEmpty(excludes)) transfer.setExcludes(excludes);
            File zip = FileCollector.collect(new Transfers().addTransfer(transfer), input.toFile(), this);
            client.uploadZip(projectName, zip, 1024 * 1024);

            if (null == jsonSettings)
                scanId = client.getSastApi().startUiJob(projectName, StringUtils.isEmpty(node) ? Base.DEFAULT_PTAI_NODE_NAME : node);
            else
                scanId = client.getSastApi().startJsonJob(
                        projectName,
                        StringUtils.isEmpty(node) ? Base.DEFAULT_PTAI_NODE_NAME : node,
                        new ObjectMapper().writeValueAsString(jsonSettings.fix()),
                        null == jsonPolicy ? "" : new ObjectMapper().writeValueAsString(jsonPolicy));

            GracefulShutdown shutdown = new GracefulShutdown(this, client, scanId);
            Runtime.getRuntime().addShutdownHook(shutdown);

            log("SAST job number is %d", scanId);

            JobState state = null;
            int pos = 0;
            do {
                state = client.getSastApi().getScanJobState(scanId, pos);
                if (state.getPos() != pos) {
                    String[] lines = state.getLog().split("\\r?\\n");
                    for (String line : lines)
                        log(line);
                }
                pos = state.getPos();
                if (!state.getStatus().equals(JobState.StatusEnum.UNKNOWN)) break;
                Thread.sleep(2000);
            } while (true);
            shutdown.setStopped(true);

            List<String> results = client.getSastApi().getJobResults(scanId);
            if ((null != results) && (!results.isEmpty())) {
                log("AST results will be stored to %s", output);
                if (!output.toFile().exists())
                    Files.createDirectories(output);
            }
            for (String result : results) {
                File data = client.getSastApi().getJobResult(scanId, result);
                String fileName = output + File.separator + result.replaceAll("REPORTS/", "");
                if (result.endsWith("status.code")) {
                    res = Integer.parseInt(FileUtils.readFileToString(data, StandardCharsets.UTF_8.name()));
                    if (ExitCode.CODES.containsKey(res))
                        log("Status code %d: %s", res, ExitCode.CODES.get(res));
                    Files.write(Paths.get(fileName), res.toString().getBytes());
                } else
                    Files.copy(data.toPath(), Paths.get(fileName), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (Exception e) {
            log(e);
        }
        return res;
    }
}
