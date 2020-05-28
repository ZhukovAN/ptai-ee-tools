package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.SlimSastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import lombok.extern.log4j.Log4j2;
import picocli.CommandLine;

@Log4j2
@CommandLine.Command(
        name = "slim-ui-ast",
        sortOptions = false,
        description = "Calls PT AI EE for AST using integration server. Project settings are defined in the PT AI viewer UI",
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:AST complete, policy (if set up) assessment success",
                "1:AST complete, policy (if set up) assessment failed",
                "2:AST complete, policy (if set up) assessment success, minor warnings were reported",
                "3:AST failed", "1000:Invalid input"})
public class SlimUiAst extends BaseSlimAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI integration service URL, i.e. https://ptai.domain.org:8443")
    protected URL url;

    @CommandLine.Option(
            names = {"-u", "--user"},
            required = true, order = 2,
            paramLabel = "<name>",
            description = "PT AI integration service account name")
    protected String username = null;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true, order = 3,
            paramLabel = "<token>",
            description = "PT AI integration service API token")
    protected String token = null;

    @CommandLine.Option(
            names = {"--input"}, order = 4,
            required = true,
            paramLabel = "<path>",
            description = "Source file or folder to scan")
    protected Path input = Paths.get(System.getProperty("user.dir"));

    @CommandLine.Option(
            names = {"--output"}, order = 5,
            paramLabel = "<path>",
            description = "Folder where AST reports are to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(Base.SAST_FOLDER);

    @CommandLine.Option(
            names = {"-p", "--project"}, order = 6,
            required = true,
            paramLabel = "<name>",
            description = "Project name how it is setup and seen in the PT AI viewer")
    protected String project = null;

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
            names = {"-n", "--node"},
            required = true, order = 9,
            paramLabel = "<name>",
            description = "Node name or tag for SAST to be executed on")
    protected String node = Base.DEFAULT_PTAI_NODE_NAME;

    @CommandLine.Option(
            names = {"--truststore"}, order = 10,
            paramLabel = "<path>",
            description = "Path to file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"--truststore-pass"}, order = 11,
            paramLabel = "<password>",
            description = "Truststore password")
    protected String truststorePassword = null;

    @CommandLine.Option(
            names = {"--truststore-type"}, order = 12,
            paramLabel = "<type>",
            description = "Truststore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
    protected String truststoreType = "JKS";

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 13,
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @Override
    public Integer call() throws Exception {
        switch (execute()) {
            case UNSTABLE: return BaseSlimAst.ExitCode.WARNINGS.getCode();
            case FAILURE: return BaseSlimAst.ExitCode.FAILED.getCode();
            case SUCCESS: return BaseSlimAst.ExitCode.SUCCESS.getCode();
            default: return ExitCode.ERROR.getCode();
        }
    }

    public PtaiResultStatus execute() {
        if (verbose) {
            log.info("AST parameters are:");
            log.info("PT AI EE URL: {}", url);
            log.info("Project: {}", project);
            log.info("Input: {}", input.toString());
            log.info("Output: {}", output.toString());
            log.info("Node: {}", node);
            log.info("User: {}", username);
            log.info("Includes: {}", includes);
            log.info("Excludes: {}", excludes);
            log.info("Truststore: {}", truststore.toString());
        }
        SlimSastJob job = SlimSastJob.builder()
                .url(url)
                .project(project)
                .input(input)
                .node(node)
                .username(username)
                .token(token)
                .output(output)
                .clientId(Plugin.CLIENT_ID)
                .clientSecret(Plugin.CLIENT_SECRET)
                .includes(includes)
                .excludes(excludes)
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
