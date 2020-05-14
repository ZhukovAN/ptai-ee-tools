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
        helpCommand = true,
        // mixinStandardHelpOptions = true, version = "0.1",
        description = "Calls PT AI EE for AST using @|bold,fg(red) deprecated|@ legacy mode. Project settings are defined in the PT AI viewer UI",
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:AST complete, policy (if set up) assessment success",
                "1:AST complete, policy (if set up) assessment failed",
                "2:AST complete, minor warnings were reported",
                "3:AST failed"})
public class LegacyUiAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--jenkins-url"},
            required = true,
            description = "Embedded Jenkins URL, i.e. https://ast.domain.org:8443")
    protected URL jenkinsUrl;

    @CommandLine.Option(
            names = {"--ptai-url"},
            required = true,
            description = "PT AI URL, i.e. https://ptai.domain.org:443")
    protected URL ptaiUrl;

    @CommandLine.Option(
            names = {"-p", "--project"},
            required = true,
            description = "Project name how it is setup and seen in the PT AI viewer")
    protected String project = null;

    @CommandLine.Option(
            names = {"-j", "--job-name"},
            required = true,
            description = "SAST embedded job full name, i.e. SAST/UI-managed SAST pipeline")
    protected String sastJob = null;

    @CommandLine.Option(
            names = {"-n", "--node"},
            required = true,
            description = "Node name or tag for SAST to be executed on")
    protected String node = Base.DEFAULT_PTAI_NODE_NAME;

    @CommandLine.Parameters(index = "0", description = "Source folder to scan")
    protected Path input = Paths.get(System.getProperty("user.dir"));

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
            names = {"--keystore"},
            required = true,
            description = "Path to file that stores client SSL certificate and key")
    protected Path keystore = null;

    @CommandLine.Option(
            names = {"--keystore-type"},
            description = "Keystore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
    protected String keystoreType = "JKS";

    @CommandLine.Option(
            names = {"--keystore-pass"},
            description = "Keystore password")
    protected String keystorePassword = null;

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
            names = {"-v", "--verbose"},
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @CommandLine.Option(
            names = {"-u", "--user"},
            required = true,
            description = "Embedded Jenkins username account name")
    protected String username = null;
    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true,
            description = "Embedded Jenkins user API token")
    protected String token = null;
    @CommandLine.Option(
            names = {"-o", "--output"},
            required = true,
            description = "Folder where AST reports are to be stored")
    protected Path output = null;

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
        job.setConsoleLog(System.out);
        job.setLogPrefix(null);
        job.setVerbose(verbose);
        return PtaiResultStatus.convert(job.execute());
    }
}
