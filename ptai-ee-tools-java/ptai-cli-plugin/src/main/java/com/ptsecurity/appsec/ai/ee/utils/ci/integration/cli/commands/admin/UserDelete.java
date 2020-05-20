package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.BaseSlimAst;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import lombok.extern.log4j.Log4j2;
import picocli.CommandLine;

import java.net.URL;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Log4j2
@CommandLine.Command(
        name = "admin-user-delete",
        sortOptions = false,
        description = "Deletes existing PT AI EE integration server user",
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
        "0:User deleted successfully",
        "1:Error during user delete attempt",
        "2:Invalid input"})
public class UserDelete  extends BaseSlimAst implements Callable<Integer> {
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
            description = "PT AI integration service user name")
    protected String username = null;

    @CommandLine.Option(
            names = {"--truststore"}, order = 6,
            paramLabel = "<path>",
            description = "Path to file that stores trusted CA certificates")
    protected Path truststore = null;

    @CommandLine.Option(
            names = {"--truststore-pass"}, order = 7,
            paramLabel = "<password>",
            description = "Truststore password")
    protected String truststorePassword = null;

    @CommandLine.Option(
            names = {"--truststore-type"}, order = 8,
            paramLabel = "<type>",
            description = "Truststore file type, i.e. JKS, PKCS12 etc. By default JKS is used")
    protected String truststoreType = "JKS";

    @CommandLine.Option(
            names = {"--use-id"}, order = 9,
            description = "Use user ID instead of name")
    protected boolean useId = false;

    @CommandLine.Option(
            names = {"-v", "--verbose"}, order = 9,
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
            if (useId)
                client.getAdminApi().deleteUser(Long.valueOf(username), null);
            else
                client.getAdminApi().deleteUser(null, username);
            log.info("User deleted");
            return 0;
        } catch (ApiException e) {
            processApiException("User delete", e, verbose);
            return 1;
        }
    }
}
