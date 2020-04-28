package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.JobState;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import lombok.Setter;
import org.apache.commons.cli.*;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;

public class SlimSastJob extends Base {
    protected CommandLine cli = null;

    protected void parseCommand(String[] args) {
        CommandLineParser parser = new DefaultParser();
        Options options = new Options();

        options.addOption(
                Option.builder()
                        .longOpt("url")
                        .required(true)
                        .desc("PTAI integration service URL, i.e. https://ptai.domain.org:8443")
                        .argName("url")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("project")
                        .required(true)
                        .desc("Project name how it is setup and seen in the PT AI viewer")
                        .argName("project name")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("truststore")
                        .required(false)
                        .desc("Path to file that stores trusted CA certificates")
                        .argName("file")
                        .hasArg(true).build());
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
                        .longOpt("includes")
                        .required(false)
                        .desc("Comma-separated list of files to include to scan")
                        .argName("files")
                        .hasArg(true)
                        .build());
        options.addOption(
                Option.builder()
                        .longOpt("excludes")
                        .required(false)
                        .desc("Comma-separated list of files to exclude from scan")
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
                        .required(true)
                        .desc("PT AI integration service account name")
                        .argName("name")
                        .hasArg(true).build());

        options.addOption(
                Option.builder()
                        .longOpt("token")
                        .required(true)
                        .desc("PT AI integration service API token")
                        .argName("token")
                        .hasArg(true).build());

        options.addOption(
                Option.builder()
                        .longOpt("output")
                        .required(false)
                        .desc("Folder where AST reports are to be stored")
                        .argName("folder")
                        .hasArg(true).build());
        try {
            cli = parser.parse(options, args);
            url = new URL(cli.getOptionValue("url").replaceAll("^\"|\"$", ""));
            project = cli.getOptionValue("project").replaceAll("^\"|\"$", "");

            truststore = cli.getOptionValue("truststore");
            if (null != truststore)
                truststore = truststore.replaceAll("^\"|\"$", "");

            folder = cli.getOptionValue("folder").replaceAll("^\"|\"$", "");
            folder = new File(folder).getAbsolutePath();
            // "^\"|\"$" means "remove optional opening and closing quotes"
            includes = Optional.ofNullable(cli.getOptionValue("includes")).orElse("**/*").replaceAll("^\"|\"$", "");
            excludes = Optional.ofNullable(cli.getOptionValue("excludes")).orElse("").replaceAll("^\"|\"$", "");
            node = cli.getOptionValue("node").replaceAll("^\"|\"$", "");
            username = cli.getOptionValue("username").replaceAll("^\"|\"$", "");
            token = cli.getOptionValue("token").replaceAll("^\"|\"$", "");
            if (cli.hasOption("output"))
                output = cli.getOptionValue("output").replaceAll("^\"|\"$", "");
            else
                output = Paths.get(SAST_FOLDER).toAbsolutePath().toString();
            output = new File(output).getAbsolutePath();

            verbose = cli.hasOption("verbose");
        } catch (ParseException | IOException e) {
            HelpFormatter fmt = new HelpFormatter();
            fmt.printHelp("java -jar generic-client-lib.jar", options, true);
            cli = null;
        }
    }

    protected URL url = null;
    protected String project = null;

    protected String truststore = null;

    protected String folder = null;
    protected String includes = null;
    protected String excludes = null;
    protected String node = null;
    protected String username = null;
    protected String token = null;
    protected String output = null;

    public void main(String[] args) {
        switch (execute(args)) {
            case UNSTABLE: System.exit(2);
            case FAILURE: System.exit(1);
            case SUCCESS: System.exit(0);
            default: System.exit(2);
        }
    }

    public static PtaiResultStatus execute(String[] theArgs) {
        SlimSastJob job = new SlimSastJob();
        job.setConsoleLog(System.out);
        job.setLogPrefix(null);
        job.parseCommand(theArgs);
        if (null == job.cli) return PtaiResultStatus.FAILURE;
        return job.execute();
    }

    protected PtaiResultStatus processRetCode(int retCode) {
        return PtaiResultStatus.UNKNOWN;
    }

    protected PtaiResultStatus execute() {
        Client client = null;
        Integer scanId = null;
        try {
            client = new Client();
            client.setUrl(url.toString());
            client.setClientId("ptai-cli-plugin");
            client.setClientSecret("ir5qWH61Pvr2FG54aC3YSeq0TGCoudod");
            client.setConsoleLog(this.consoleLog);
            client.setVerbose(verbose);
            client.setLogPrefix(this.logPrefix);

            if (null != truststore)
                client.setTrustStoreFile(truststore);

            client.setUserName(username);
            client.setPassword(token);
            client.init();

            Transfer transfer = new Transfer();
            if (StringUtils.isNotEmpty(includes)) transfer.setIncludes(includes);
            if (StringUtils.isNotEmpty(excludes)) transfer.setExcludes(excludes);
            File zip = FileCollector.collect(new Transfers().addTransfer(transfer), new File(folder), null);
            client.uploadZip(project, zip, 1024 * 1024);

            scanId = client.getSastApi().startUiJob(project, node);
            GracefulShutdown shutdown = new GracefulShutdown(client, scanId);
            Runtime.getRuntime().addShutdownHook(shutdown);

            log("SAST job number is %d\r\n", scanId);

            JobState state = null;
            int pos = 0;
            do {
                state = client.getSastApi().getScanJobState(scanId, pos);
                if (state.getPos() != pos) {
                    String[] lines = state.getLog().split("\\r?\\n");
                    for (String line : lines)
                        log("%s\r\n", line);
                }
                pos = state.getPos();
                if (!state.getStatus().equals(JobState.StatusEnum.UNKNOWN)) break;
                Thread.sleep(2000);
            } while (true);
            shutdown.client = null;

            List<String> results = client.getSastApi().getJobResults(scanId);
            if ((null != results) && (!results.isEmpty())) {
                log("AST results will be stored to " + output);
                Files.createDirectories(Paths.get(output));
            }
            for (String result : results) {
                File data = client.getSastApi().getJobResult(scanId, result);
                String fileName = output + File.separator + result.replaceAll("REPORTS/", "");
                if (result.endsWith("status.code")) {
                    Integer code = Integer.parseInt(FileUtils.readFileToString(data, StandardCharsets.UTF_8.name()));
                    Files.write(Paths.get(fileName), code.toString().getBytes());
                } else
                    Files.copy(data.toPath(), Paths.get(fileName));
            }
            return PtaiResultStatus.valueOf(state.getStatus().getValue());
        } catch (Exception e) {
            log(e);
            return PtaiResultStatus.FAILURE;
        }
    }

    class GracefulShutdown extends Thread {
        @Setter
        protected boolean stopped = false;

        protected Client client;
        protected Integer scanId;

        public GracefulShutdown(Client client, Integer scanId) {
            this.client = client;
            this.scanId = scanId;
        }

        public void run() {
            if (stopped) return;
            if ((null != client) && (null != scanId)) {
                try {
                    client.getSastApi().stopScan(scanId);
                } catch (ApiException e1) {
                    log("Build %d stop failed", scanId);
                }
            }
        }
    }
}
