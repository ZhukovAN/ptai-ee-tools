package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.SastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.extern.java.Log;
import org.apache.commons.lang3.StringUtils;
import picocli.CommandLine;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;
import java.util.logging.Level;
import java.util.stream.Stream;

@Log
@CommandLine.Command(
        name = "json-ast",
        sortOptions = false,
        description = "Calls PT AI for AST. Project settings and policy are defined with JSON files",
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:AST complete, policy (if set up) assessment success",
                "1:AST complete, policy (if set up) assessment failed",
                "2:AST complete, policy (if set up) assessment success, minor warnings were reported",
                "3:AST failed", "1000:Invalid input"})
public class JsonAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI integration service URL, i.e. https://ptai.domain.org:8443")
    protected URL url;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true, order = 2,
            paramLabel = "<token>",
            description = "PT AI integration service API token")
    protected String token = null;

    @CommandLine.Option(
            names = {"--input"}, order = 3,
            required = true,
            paramLabel = "<path>",
            description = "Source file or folder to scan")
    protected Path input = Paths.get(System.getProperty("user.dir"));

    @CommandLine.Option(
            names = {"--output"}, order = 4,
            paramLabel = "<path>",
            description = "Folder where AST reports are to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(Base.DEFAULT_SAST_FOLDER);

    @CommandLine.Option(
            names = {"--settings-json"}, order = 5,
            paramLabel = "<path>",
            required = true,
            description = "Path to JSON-defined scan settings")
    protected Path jsonSettings = null;

    @CommandLine.Option(
            names = {"--policy-json"}, order = 6,
            paramLabel = "<path>",
            description = "Path to JSON-defined AST policy. If this option is not defined, existing policy from database will be used. So if you need to override existing policy, use policy file with empty [] value")
    protected Path jsonPolicy = null;

    @CommandLine.Option(
            names = {"-i", "--includes"}, order = 7,
            paramLabel = "<pattern>",
            description = "Comma-separated list of files to include to scan. The string is a comma separated list of includes for an Ant fileset eg. '**/*.jar'" +
                    "(see http://ant.apache.org/manual/dirtasks.html#patterns). The base directory for this fileset is the sources folder")
    protected String includes = null;

    @CommandLine.Option(
            names = {"-e", "--excludes"}, order = 8,
            paramLabel = "<pattern>",
            description = "Comma-separated list of files to exclude from scan. The syntax is the same as for includes")
    protected String excludes = null;

    @CommandLine.Option(
            names = {"-n", "--node"}, order = 9,
            paramLabel = "<name>",
            description = "Node name or tag for SAST to be executed on")
    protected String node = Base.DEFAULT_PTAI_NODE_NAME;

    @CommandLine.Option(
            names = {"--truststore"}, order = 10,
            paramLabel = "<path>",
            description = "Path to PEM file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.ArgGroup(exclusive = false)
    BaseAst.Report report;

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 99,
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @Override
    public Integer call() throws Exception {
        switch (execute()) {
            case UNSTABLE: return BaseAst.ExitCode.WARNINGS.getCode();
            case FAILURE: return BaseAst.ExitCode.FAILED.getCode();
            case SUCCESS: return BaseAst.ExitCode.SUCCESS.getCode();
            default: return 3;
        }
    }

    public PtaiResultStatus execute() throws IOException {
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);

        ScanSettings settings = null;
        try (Stream<String> stream = Files.lines(jsonSettings, StandardCharsets.UTF_8)) {
            StringBuilder builder = new StringBuilder();
            stream.forEach(s -> builder.append(s).append("\n"));
            settings = jsonMapper.readValue(builder.toString(), ScanSettings.class);
            if (StringUtils.isEmpty(settings.getSite())) {
                settings.setSite("http://localhost:8080");
                log.warning("It is strictly recommended to set site address in scan settings");
            }
        } catch (JsonParseException | JsonMappingException e) {
            log.severe("JSON settings file parse failed");
            log.log(Level.FINE, "Error details", e);
            return PtaiResultStatus.FAILURE;
        } catch (IOException e) {
            log.severe("JSON settings file read failed");
            log.log(Level.FINE, "Error details", e);
            return PtaiResultStatus.FAILURE;
        }

        Policy[] policy = null;
        if (null != jsonPolicy) {
            StringBuilder builder = new StringBuilder();
            try (Stream<String> stream = Files.lines(jsonPolicy, StandardCharsets.UTF_8)) {
                stream.forEach(s -> builder.append(s).append("\n"));
                policy = jsonMapper.readValue(builder.toString(), Policy[].class);
            } catch (JsonParseException | JsonMappingException e) {
                log.severe("JSON policy file parse failed");
                log.log(Level.FINE, "Error details", e);
                return PtaiResultStatus.FAILURE;
            } catch (IOException e) {
                log.severe("JSON policy file read failed");
                log.log(Level.FINE, "Error details", e);
                return PtaiResultStatus.FAILURE;
            }
        }

        SastJob job = SastJob.builder()
                .url(url)
                .input(input)
                .node(node)
                .token(token)
                .output(output)
                .includes(includes)
                .excludes(excludes)
                .jsonSettings(settings)
                .jsonPolicy(policy)
                .report(report)
                .build();
        if (null != truststore) {
            String pem = new String(Files.readAllBytes(truststore), StandardCharsets.UTF_8);
            job.setServerCaCertificates(pem);
        }
        job.setConsole(System.out);
        job.setPrefix("");
        job.setVerbose(verbose);
        return PtaiResultStatus.convert(job.execute());
    }
}
