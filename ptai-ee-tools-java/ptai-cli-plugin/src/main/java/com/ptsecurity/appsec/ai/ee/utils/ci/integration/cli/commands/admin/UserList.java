package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.User;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.AbstractIntegrationApiCommand;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
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
        // mixinStandardHelpOptions = true, version = "0.1",
        helpCommand = true,
        description = "Lists PT AI EE integration server users")
public class UserList extends AbstractIntegrationApiCommand implements Callable<Integer> {
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
