package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.User;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.UserData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseSlimAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import lombok.extern.log4j.Log4j2;
import picocli.CommandLine;

import java.net.URL;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@Log4j2
@CommandLine.Command(
        name = "admin-user-create",
        sortOptions = false,
        description = "Creates new PT AI EE integration server user",
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:User created successfully",
                "1:Error during user add attempt",
                "2:Invalid input"})
public class UserCreate extends BaseSlimAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI integration service URL, i.e. https://ptai.domain.org:8443")
    protected URL url;

    @CommandLine.Option(
            names = {"-a", "--administrator"},
            required = true, order = 2,
            paramLabel = "<user>",
            description = "PT AI integration service administrator account name")
    protected String admin = null;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true, order = 3,
            paramLabel = "<token>",
            description = "PT AI integration service administrator API token")
    protected String token = null;

    @CommandLine.Option(
            names = {"-u", "--user"},
            required = true, order = 4,
            paramLabel = "<user>",
            description = "New PT AI integration service user name")
    protected String username = null;

    @CommandLine.Option(
            names = {"-p", "--password"},
            arity = "0..1", interactive = true,
            required = true, order = 5,
            paramLabel = "<password>",
            description = "New PT AI integration service user password")
    protected String password = null;

    @CommandLine.Option(
            names = {"--is-admin"},
            order = 6,
            description = "Grant administrator role to new user")
    protected boolean isAdmin = false;

    @CommandLine.Option(
            names = {"--truststore"}, order = 7,
            paramLabel = "<path>",
            description = "Path to file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"--truststore-pass"}, order = 8,
            paramLabel = "<password>",
            description = "Truststore password")
    protected String truststorePassword = null;

    @CommandLine.Option(
            names = {"--truststore-type"}, order = 9,
            paramLabel = "<type>",
            description = "Truststore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
    protected String truststoreType = "JKS";

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 10,
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

            UserData userData = new UserData();
            userData.setName(username);
            userData.setPassword(password);
            userData.setRoles(isAdmin ? Arrays.asList("ADMIN", "USER") : Arrays.asList("USER"));
            User user = client.getAdminApi().postSignup(userData);
            String roles = String.join(", ", user.getRoles().stream().map(r -> r.getName()).collect(Collectors.toList()));
            log.info("User: {} [{}] created", user.getName(), roles);
            return 0;
        } catch (Exception e) {
            processApiException("User create", e, verbose);
            return 1;
        }
    }
}
