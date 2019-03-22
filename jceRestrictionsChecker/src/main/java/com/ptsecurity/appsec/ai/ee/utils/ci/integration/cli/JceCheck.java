package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import org.apache.commons.cli.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;

public class JceCheck {
    protected static CommandLine cli = null;

    protected static void parseCommand(String[] args) {
        CommandLineParser parser = new DefaultParser();
        Options options = new Options();

        options.addOption(
                Option.builder()
                        .longOpt("keystore")
                        .required(true)
                        .desc("Path to PEM file that stores client SSL certificate and key")
                        .argName("file")
                        .hasArg(true).build());
        options.addOption(
                Option.builder()
                        .longOpt("keystore-pass")
                        .required(false)
                        .desc("Keystore password")
                        .argName("password")
                        .hasArg(true)
                        .build());

        try {
            cli = parser.parse(options, args);
            keystore = cli.getOptionValue("keystore").replaceAll("^\"|\"$", "");
            keystorePass = Optional.ofNullable(cli.getOptionValue("keystore-pass")).orElse("").replaceAll("^\"|\"$", "");

        } catch (ParseException e) {
            HelpFormatter fmt = new HelpFormatter();
            fmt.printHelp("java -jar generic-client-lib.jar", options, true);
            cli = null;
        }
    }

    protected static String keystore = "";
    protected static String keystorePass = "";

    public static void main(String[] args) {
        parseCommand(args);
        if (null == cli) return;
        execute();
    }

    protected static void execute() {
        try {
            Base base = new Base();
            base.setUrl("http://127.0.0.1:8080");
            // base.setKeyPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keystores\\CB5352E43AC14295\\ssl.client.brief.pem"))));
            base.setKeyPem(new String(Files.readAllBytes(Paths.get(keystore))));
            base.setKeyPassword(keystorePass);
            base.baseInit();
            System.out.println("JCE check done");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
