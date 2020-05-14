package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.SlimSastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import picocli.CommandLine;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

@Log4j2
@CommandLine.Command(
        name = "slim-json-ast",
        helpCommand = true,
        // mixinStandardHelpOptions = true, version = "0.1",
        description = "Calls PT AI EE for AST using integration server. Project settings and policy are defined with JSON files",
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:AST complete, policy (if set up) assessment success",
                "1:AST complete, policy (if set up) assessment failed",
                "2:AST complete, minor warnings were reported",
                "3:AST failed"})
public class SlimJsonAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--url"},
            required = true,
            description = "PT AI integration service URL, i.e. https://ptai.domain.org:8443")
    protected URL url;

    @CommandLine.Option(
            names = {"--truststore"},
            description = "Path to file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"--truststore-type"},
            description = "Truststore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
    protected String truststoreType = "JKS";

    @CommandLine.Option(
            names = {"--truststore-pass"},
            description = "Truststore password")
    protected String truststorePassword = null;

    @CommandLine.Option(
            names = {"-i", "--includes"},
            description = "Comma-separated list of files to include to scan. The string is a comma separated list of includes for an Ant fileset eg. '**/*.jar'" +
                    "(see http://ant.apache.org/manual/dirtasks.html#patterns). The base directory for this fileset is the sources folder")
    protected String includes = null;

    @CommandLine.Option(
            names = {"-e", "--excludes"},
            description = "Comma-separated list of files to exclude from scan. The syntax is the same as for includes")
    protected String excludes = null;

    @CommandLine.Option(
            names = {"-n", "--node"},
            required = true,
            description = "Node name or tag for SAST to be executed on")
    protected String node = Base.DEFAULT_PTAI_NODE_NAME;

    @CommandLine.Option(
            names = {"-u", "--user"},
            required = true,
            description = "PT AI integration service account name")
    protected String username = null;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true,
            description = "PT AI integration service API token")
    protected String token = null;

    @CommandLine.Option(
            names = {"-o", "--output"},
            description = "Folder where AST reports are to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(Base.SAST_FOLDER);

    @CommandLine.Option(
            names = {"--settings-json"},
            required = true,
            description = "JSON-defined scan settings")
    protected Path jsonSettings = null;

    @CommandLine.Option(
            names = {"--policy-json"},
            description = "JSON-defined AST policy")
    protected Path jsonPolicy = null;

    @CommandLine.Option(
            names = {"-v", "--verbose"},
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @CommandLine.Parameters(index = "0", description = "Source folder to scan")
    protected Path input = Paths.get(System.getProperty("user.dir"));

    @Override
    public Integer call() throws Exception {
        switch (execute()) {
            case UNSTABLE: return 2;
            case FAILURE: return 1;
            case SUCCESS: return 0;
            default: return 3;
        }
    }

    public PtaiResultStatus execute() {
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
                log.warn("It is strictly recommended to set site address in scan settings");
            }
        } catch (JsonParseException | JsonMappingException e) {
            log.error("JSON settings file parse failed");
            log.debug("Error details", e);
            return PtaiResultStatus.FAILURE;
        } catch (IOException e) {
            log.error("JSON settings file read failed");
            log.debug("Error details", e);
            return PtaiResultStatus.FAILURE;
        }

        if (verbose) {
            log.info("AST parameters are:");
            log.info("PT AI EE URL: {}", url);
            log.info("Project: {}", settings.getProjectName());
            log.info("Input: {}", input.toString());
            log.info("Output: {}", output.toString());
            log.info("Node: {}", node);
            log.info("User: {}", username);
            log.info("Includes: {}", includes);
            log.info("Excludes: {}", excludes);
            log.info("Truststore: {}", truststore.toString());
        }

        Policy[] policy = null;
        if (null != jsonPolicy) {
            StringBuilder builder = new StringBuilder();
            try (Stream<String> stream = Files.lines(jsonPolicy, StandardCharsets.UTF_8)) {
                stream.forEach(s -> builder.append(s).append("\n"));
                policy = jsonMapper.readValue(builder.toString(), Policy[].class);
            } catch (JsonParseException | JsonMappingException e) {
                log.error("JSON policy file parse failed");
                log.debug("Error details", e);
                return PtaiResultStatus.FAILURE;
            } catch (IOException e) {
                log.error("JSON policy file read failed");
                log.debug("Error details", e);
                return PtaiResultStatus.FAILURE;
            }
        }

        SlimSastJob job = SlimSastJob.builder()
                .url(url)
                .input(input)
                .node(node)
                .username(username)
                .token(token)
                .output(output)
                .clientId(Plugin.CLIENT_ID)
                .clientSecret(Plugin.CLIENT_SECRET)
                .includes(includes)
                .excludes(excludes)
                .jsonSettings(settings)
                .jsonPolicy(policy)
                .truststore(truststore)
                .truststoreType(truststoreType)
                .truststorePassword(truststorePassword)
                .build();
        job.setConsoleLog(System.out);
        job.setLogPrefix(null);
        job.setVerbose(verbose);
        return PtaiResultStatus.convert(job.execute());
    }
}
