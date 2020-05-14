package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.User;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.UserData;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.AbstractIntegrationApiCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import picocli.CommandLine;

import java.net.URL;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@Log4j2
@CommandLine.Command(
        name = "admin-user-add",
        // mixinStandardHelpOptions = true, version = "0.1",
        helpCommand = true,
        description = "Adds new PT AI EE integration server user")
public class UserAdd extends AbstractIntegrationApiCommand implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--url"},
            required = true,
            description = "PT AI EE integration service URL, i.e. https://ptai.domain.org:8443")
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
            names = {"-a", "--admin"},
            required = true,
            description = "PT AI EE integration service administrator account name")
    protected String admin = null;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true,
            description = "PT AI EE integration service API token")
    protected String token = null;

    @CommandLine.Option(
            names = "--user",
            required = true,
            description = "New PT AI EE integration service user name")
    String username;

    @CommandLine.Option(
            names = "--password", arity = "0..1", interactive = true, required = true,
            description = "New PT AI EE integration service user password")
    String password;

    @CommandLine.Option(
            names = {"-v", "--verbose"},
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
            userData.setRoles(Arrays.asList("USER"));
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
