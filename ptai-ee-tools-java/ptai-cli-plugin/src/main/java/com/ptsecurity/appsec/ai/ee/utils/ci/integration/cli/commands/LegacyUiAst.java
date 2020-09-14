package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.LegacySastJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import lombok.extern.log4j.Log4j2;
import picocli.CommandLine;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Log4j2
@CommandLine.Command(
        name = "legacy-ui-ast",
        sortOptions = false,
        description = "Calls PT AI EE for AST using @|bold,fg(red) deprecated|@ legacy mode. Project settings are defined in the PT AI viewer UI",
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:AST complete, policy (if set up) assessment success",
                "1:AST complete, policy (if set up) assessment failed",
                "2:AST complete, policy (if set up) assessment success, minor warnings were reported",
                "3:AST failed", "1000:Invalid input"})
public class LegacyUiAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--ptai-url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI EE URL, i.e. https://ptai.domain.org:443")
    protected URL ptaiUrl;

    @CommandLine.Option(
            names = {"--jenkins-url"},
            required = true, order = 2,
            paramLabel = "<url>",
            description = "Embedded Jenkins URL, i.e. https://ast.domain.org:8443")
    protected URL jenkinsUrl;

    @CommandLine.Option(
            names = {"-u", "--user"},
            required = true, order = 3,
            paramLabel = "<name>",
            description = "Embedded Jenkins user account name")
    protected String username = null;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true, order = 4,
            paramLabel = "<token>",
            description = "Embedded Jenkins user API token or password")
    protected String token = null;

    @CommandLine.Option(
            names = {"-j", "--job-name"},
            required = true, order = 5,
            paramLabel = "<name>",
            description = "SAST embedded job full name, i.e. SAST/UI-managed SAST pipeline")
    protected String sastJob = null;

    @CommandLine.Option(
            names = {"--input"}, order = 6,
            required = true,
            paramLabel = "<path>",
            description = "Source file or folder to scan")
    protected Path input = Paths.get(System.getProperty("user.dir"));

    @CommandLine.Option(
            names = {"--output"}, order = 7,
            paramLabel = "<path>",
            description = "Folder where AST reports are to be stored. By default .ptai folder is used")
    protected Path output = Paths.get(System.getProperty("user.dir")).resolve(Base.DEFAULT_SAST_FOLDER);

    @CommandLine.Option(
            names = {"-p", "--project"}, order = 8,
            required = true,
            paramLabel = "<name>",
            description = "Project name how it is setup and seen in the PT AI viewer")
    protected String project = null;

    @CommandLine.Option(
            names = {"-i", "--includes"}, order = 9,
            paramLabel = "<pattern>",
            description = "Comma-separated list of files to include to scan. The string is a comma separated list of includes for an Ant fileset eg. '**/*.jar'" +
                    "(see http://ant.apache.org/manual/dirtasks.html#patterns). The base directory for this fileset is the sources folder")
    protected String includes = null;

    @CommandLine.Option(
            names = {"-e", "--excludes"}, order = 10,
            paramLabel = "<pattern>",
            description = "Comma-separated list of files to exclude from scan. The syntax is the same as for includes")
    protected String excludes = null;

    @CommandLine.Option(
            names = {"-n", "--node"},
            required = true, order = 11,
            paramLabel = "<name>",
            description = "Node name or tag for SAST to be executed on")
    protected String node = Base.DEFAULT_PTAI_NODE_NAME;

    @CommandLine.Option(
            names = {"--keystore"},
            required = true, order = 12,
            paramLabel = "<path>",
            description = "Path to file that stores client SSL certificate and key")
    protected Path keystore = null;

    @CommandLine.Option(
            names = {"--keystore-type"},
            paramLabel = "<type>", order = 13,
            description = "Keystore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
    protected String keystoreType = "JKS";

    @CommandLine.Option(
            names = {"--keystore-pass"},
            paramLabel = "<password>", order = 14,
            description = "Keystore password")
    protected String keystorePassword = null;

    @CommandLine.Option(
            names = {"--truststore"}, order = 15,
            paramLabel = "<path>",
            description = "Path to file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"--truststore-pass"}, order = 16,
            paramLabel = "<password>",
            description = "Truststore password")
    protected String truststorePassword = null;

    @CommandLine.Option(
            names = {"--truststore-type"}, order = 17,
            paramLabel = "<type>",
            description = "Truststore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
    protected String truststoreType = "JKS";

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 18,
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @Override
    public Integer call() throws Exception {
        switch (execute()) {
            case UNSTABLE: return BaseSlimAst.ExitCode.WARNINGS.getCode();
            case FAILURE: return BaseSlimAst.ExitCode.FAILED.getCode();
            case SUCCESS: return BaseSlimAst.ExitCode.SUCCESS.getCode();
            default: return BaseSlimAst.ExitCode.ERROR.getCode();
        }
    }

    public PtaiResultStatus execute() {
        if (verbose) {
            log.info("AST parameters are:");
            log.info("PT AI EE URL: {}", ptaiUrl);
            log.info("Embedded Jenkins URL: {}", jenkinsUrl);
            log.info("AST job: {}", sastJob);
            log.info("Project: {}", project);
            log.info("Input: {}", input.toString());
            log.info("Output: {}", output.toString());
            log.info("Node: {}", node);
            log.info("User: {}", username);
            log.info("Includes: {}", includes);
            log.info("Excludes: {}", excludes);
            log.info("Truststore: {}", truststore.toString());
            log.info("Keystore: {}", keystore.toString());
        }
        LegacySastJob job = LegacySastJob.builder()
                .jenkinsUrl(jenkinsUrl)
                .ptaiUrl(ptaiUrl)
                .sastJob(sastJob)
                .project(project)
                .input(input)
                .output(output)
                .node(node)
                .truststore(truststore)
                .truststoreType(truststoreType)
                .truststorePass(truststorePassword)
                .keystore(keystore)
                .keystoreType(keystoreType)
                .keystorePass(keystorePassword)
                .includes(includes)
                .excludes(excludes)
                .username(username)
                .password(token).build();
        job.setConsole(System.out);
        job.setLogPrefix(null);
        job.setVerbose(verbose);
        return PtaiResultStatus.convert(job.execute());
    }
}
