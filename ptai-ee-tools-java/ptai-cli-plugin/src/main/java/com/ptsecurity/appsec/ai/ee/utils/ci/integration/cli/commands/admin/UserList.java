package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.User;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseSlimAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import lombok.extern.log4j.Log4j2;
import picocli.CommandLine;

import java.net.URL;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import static org.fusesource.jansi.Ansi.Color.*;
import static org.fusesource.jansi.Ansi.ansi;

@Log4j2
@CommandLine.Command(
        name = "admin-user-list",
        sortOptions = false,
        description = "Lists PT AI EE integration server users",
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Error",
                "2:Invalid input"})

public class UserList extends BaseSlimAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI integration service URL, i.e. https://ptai.domain.org:8443")
    protected URL url;

    @CommandLine.Option(
            names = {"-a", "--administrator"},
            required = true, order = 2,
            paramLabel = "<name>",
            description = "PT AI integration service administrator account name")
    protected String admin = null;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true, order = 3,
            paramLabel = "<token>",
            description = "PT AI integration service administrator API token")
    protected String token = null;

    @CommandLine.Option(
            names = {"--truststore"}, order = 4,
            paramLabel = "<path>",
            description = "Path to file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"--truststore-pass"}, order = 5,
            paramLabel = "<password>",
            description = "Truststore password")
    protected String truststorePassword = null;

    @CommandLine.Option(
            names = {"--truststore-type"}, order = 6,
            paramLabel = "<type>",
            description = "Truststore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
    protected String truststoreType = "JKS";

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 7,
            description = "Provide verbose console log output")
    protected boolean verbose = false;

    @Override
    public Integer call() throws Exception {
        try {
            Client client = new Client();
            client.setUrl(url.toString());
            client.setClientId(Plugin.CLIENT_ID);
            client.setClientSecret(Plugin.CLIENT_SECRET);
            client.setUserName(admin);
            client.setPassword(token);
            if (null != truststore) {
                client.setTrustStoreFile(truststore.toAbsolutePath().toString());
                client.setTrustStoreType(truststoreType);
                client.setTrustStorePassword(truststorePassword);
            }
            client.init();
            List<User> users = client.getAdminApi().getUsers();
            for (User user : users) {
                String roles = String.join(", ", user.getRoles().stream().map(r -> r.getName()).collect(Collectors.toList()));
                System.out.println(ansi()
                        .a("User: #").fg(CYAN).a(user.getId())
                        .reset()
                        .a(" " + user.getName() + " [" + roles + "]"));
            }
            return 0;
        } catch (ApiException e) {
            processApiException("User list", e, verbose);
            return 1;
        }
    }
}
