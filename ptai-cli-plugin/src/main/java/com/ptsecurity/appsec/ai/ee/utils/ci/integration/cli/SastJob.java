package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import org.apache.commons.cli.*;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Optional;
import java.util.UUID;

public class SastJob {
    protected static CommandLine cli = null;

    protected static void parseCommand(String[] args) {
        CommandLineParser parser = new DefaultParser();
        Options options = new Options();

        options.addOption(
                Option.builder()
                        .longOpt("jenkins-url")
                        .required(true)
                        .desc("Jenkins URL, i.e. https://jenkins.domain.org:8443/jenkins")
                        .argName("url")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("ptai-url")
                        .required(true)
                        .desc("PTAI URL, i.e. https://ptaisrv.domain.org:443")
                        .argName("url")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("sast-job")
                        .required(true)
                        .desc("SAST job full name, i.e. SAST/UI-managed SAST pipeline")
                        .argName("job name")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("ptai-project")
                        .required(true)
                        .desc("Project name how it is setup and seen in the PT AI Viewer")
                        .argName("project name")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("truststore")
                        .required(true)
                        .desc("Path to file that stores trusted CA certificates")
                        .argName("file")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("truststore-type")
                        .required(false)
                        .desc("Truststore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
                        .argName("type")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("truststore-pass")
                        .required(false)
                        .desc("Truststore password")
                        .argName("password")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("keystore")
                        .required(true)
                        .desc("Path to file that stores client SSL certificate and key")
                        .argName("file")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("keystore-type")
                        .required(false)
                        .desc("Keystore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
                        .argName("type")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("keystore-pass")
                        .required(false)
                        .desc("Keystore password")
                        .argName("password")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("folder")
                        .required(true)
                        .desc("Source folder to scan")
                        .argName("folder")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("transfersJson")
                        .required(false)
                        .desc("Files to scan")
                        .argName("json")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("includes")
                        .required(false)
                        .desc("Files to include to scan")
                        .argName("files")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("excludes")
                        .required(false)
                        .desc("Files to exclude from scan")
                        .argName("files")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("node")
                        .required(true)
                        .desc("Node name or tag for SAST to be executed on")
                        .argName("name or tag")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("verbose")
                        .required(false)
                        .desc("Provide verbose console log output")
                        .hasArg(false)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("username")
                        .required(false)
                        .desc("Jenkins username account name")
                        .argName("name")
                        .hasArg(true).build());

        options.addOption(
                Option.builder()
                        .longOpt("password")
                        .required(false)
                        .desc("Jenkins username password or API token")
                        .argName("password or token")
                        .hasArg(true).build());

        try {
            cli = parser.parse(options, args);
            jenkinsUrl = new URL(cli.getOptionValue("jenkins-url").replaceAll("^\"|\"$", ""));
            ptaiUrl = new URL(cli.getOptionValue("ptai-url").replaceAll("^\"|\"$", ""));
            sastJob = cli.getOptionValue("sast-job").replaceAll("^\"|\"$", "");
            ptaiProject = cli.getOptionValue("ptai-project").replaceAll("^\"|\"$", "");

            truststore = cli.getOptionValue("truststore").replaceAll("^\"|\"$", "");
            truststoreType = Optional.ofNullable(cli.getOptionValue("truststore-type")).orElse("JKS").replaceAll("^\"|\"$", "");
            truststorePass = Optional.ofNullable(cli.getOptionValue("truststore-pass")).orElse("").replaceAll("^\"|\"$", "");
            keystore = cli.getOptionValue("keystore").replaceAll("^\"|\"$", "");
            keystoreType = Optional.ofNullable(cli.getOptionValue("keystore-type")).orElse("JKS").replaceAll("^\"|\"$", "");
            keystorePass = Optional.ofNullable(cli.getOptionValue("keystore-pass")).orElse("").replaceAll("^\"|\"$", "");

            folder = cli.getOptionValue("folder").replaceAll("^\"|\"$", "");
            folder = new File(folder).getAbsolutePath();
            transfersJson = Optional.ofNullable(cli.getOptionValue("transfersJson")).orElse("").replaceAll("^\"|\"$", "");
            includes = Optional.ofNullable(cli.getOptionValue("includes")).orElse("").replaceAll("^\"|\"$", "");
            excludes = Optional.ofNullable(cli.getOptionValue("excludes")).orElse("").replaceAll("^\"|\"$", "");
            if (StringUtils.isNotEmpty(transfersJson))
                transfers = new ObjectMapper().readValue(transfersJson, Transfers.class);
            else {
                transfers = new Transfers();
                Transfer transfer = new Transfer();
                if (StringUtils.isNotEmpty(includes))
                    transfer.setIncludes(includes);
                if (StringUtils.isNotEmpty(excludes))
                    transfer.setExcludes(excludes);
                transfers.addTransfer(transfer);
            }

            node = cli.getOptionValue("node").replaceAll("^\"|\"$", "");
            username = cli.getOptionValue("username").replaceAll("^\"|\"$", "");
            password = cli.getOptionValue("password").replaceAll("^\"|\"$", "");

            verbose = cli.hasOption("verbose");
        } catch (ParseException | IOException e) {
            HelpFormatter fmt = new HelpFormatter();
            fmt.printHelp("java -jar generic-client-lib.jar", options, true);
            cli = null;
        }
    }

    protected static URL jenkinsUrl = null;
    protected static URL ptaiUrl = null;

    protected static String sastJob = "";
    protected static String ptaiProject = "";

    protected static String truststore = "";
    protected static String truststoreType = "";
    protected static String truststorePass = "";
    protected static String keystore = "";
    protected static String keystoreType = "";
    protected static String keystorePass = "";

    protected static String folder = "";
    protected static Transfers transfers = null;
    protected static String transfersJson = "";
    protected static String includes = "";
    protected static String excludes = "";
    protected static String node = "";
    protected static String username = "";
    protected static String password = "";

    protected static boolean verbose = false;

    public static void main(String[] args) {
            switch (execute(args)) {
                case UNSTABLE: System.exit(2);
                case FAILURE: System.exit(1);
                case SUCCESS: System.exit(0);
                default: System.exit(2);
            }
    }

    protected static PtaiResultStatus execute(String[] theArgs) {
        parseCommand(theArgs);
        if (null == cli) return null;
        return execute();
    }

    protected static PtaiResultStatus execute() {
        PtaiProject ptaiPrj = new PtaiProject();
        ptaiPrj.setVerbose(verbose);
        ptaiPrj.setConsoleLog(System.out);
        ptaiPrj.setUrl(ptaiUrl.toString());
        ptaiPrj.setKeyStoreFile(keystore);
        ptaiPrj.setKeyStoreType(keystoreType);
        ptaiPrj.setKeyStorePassword(keystorePass);
        ptaiPrj.setTrustStoreFile(truststore);
        ptaiPrj.setTrustStoreType(truststoreType);
        ptaiPrj.setTrustStorePassword(truststorePass);
        ptaiPrj.setName(ptaiProject);
        // Connect to PT AI server
        try {
            // Try to authenticate
            String ptaiToken = ptaiPrj.init();
            if (StringUtils.isEmpty(ptaiToken))
                throw new PtaiServerException("PTAI server authentication failed", null);
            if (verbose)
                System.out.println("PTAI server authentication success. Token starts with " + ptaiToken.substring(0, 10));

            // Search for project
            UUID projectId = ptaiPrj.searchProject();
            if (null == projectId)
                throw new PtaiServerException("PTAI project not found", null);
            if (verbose)
                System.out.println("PTAI project found. ID starts with " + projectId.toString().substring(0, 4));
            // Upload project sources
            FileCollector collector = new FileCollector(transfers, null);
            File zip = FileCollector.collect(transfers, new File(folder), null);
            ptaiPrj.upload(zip);
            // Let's start analysis
            com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob jenkinsSastJob = new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob();
            jenkinsSastJob.setVerbose(verbose);
            jenkinsSastJob.setConsoleLog(System.out);
            jenkinsSastJob.setUrl(jenkinsUrl.toString());
            jenkinsSastJob.setJobName(sastJob);
            jenkinsSastJob.setTrustStoreFile(truststore);
            jenkinsSastJob.setTrustStoreType(truststoreType);
            jenkinsSastJob.setTrustStorePassword(truststorePass);
            jenkinsSastJob.setProjectName(ptaiPrj.getName());
            jenkinsSastJob.setNodeName(node);
            // Set authentication parameters
            if (StringUtils.isNotEmpty(username)) {
                jenkinsSastJob.setUserName(username);
                jenkinsSastJob.setPassword(password);
            }
            jenkinsSastJob.init();
            return jenkinsSastJob.execute(folder);
        } catch (JenkinsClientException | PtaiClientException e) {
            System.out.println(e.toString());
            if (verbose)
                Optional.ofNullable(e.getInner())
                        .ifPresent(inner -> inner.getMessage());
            return PtaiResultStatus.UNSTABLE;
        }
    }
}
