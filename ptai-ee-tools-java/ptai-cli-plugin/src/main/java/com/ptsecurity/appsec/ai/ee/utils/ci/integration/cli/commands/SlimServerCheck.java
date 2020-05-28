package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.BuildInfo;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentsStatus;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import lombok.extern.log4j.Log4j2;
import picocli.CommandLine;

import java.net.URL;
import java.nio.file.Path;
import java.util.concurrent.Callable;

import static com.ptsecurity.appsec.ai.ee.ptai.integration.rest.ComponentStatus.FAILURE;

@Log4j2
@CommandLine.Command(
        name = "slim-server-check",
        sortOptions = false,
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"},
        description = "Checks PT AI EE integration server connection")
public class SlimServerCheck extends BaseSlimAst implements Callable<Integer> {
    @CommandLine.Option(
            names = {"--url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI integration service URL, i.e. https://ptai.domain.org:8443")
    protected URL url;

    @CommandLine.Option(
            names = {"-u", "--user"},
            required = true, order = 2,
            paramLabel = "<name>",
            description = "PT AI integration service account name")
    protected String username = null;

    @CommandLine.Option(
            names = {"-t", "--token"},
            required = true, order = 3,
            paramLabel = "<token>",
            description = "PT AI integration service API token")
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
    protected boolean verbose = false;    @Override

    public Integer call() throws Exception {
        try {
            Client client = new Client();
            client.setUrl(url.toString());
            client.setClientId(Plugin.CLIENT_ID);
            client.setClientSecret(Plugin.CLIENT_SECRET);
            client.setUserName(username);
            client.setPassword(token);
            if (null != truststore) {
                client.setTrustStoreFile(truststore.toAbsolutePath().toString());
                client.setTrustStoreType(truststoreType);
                client.setTrustStorePassword(truststorePassword);
            }
            client.init();
            BuildInfo buildInfo = client.getPublicApi().getBuildInfo();
            String buildInfoText = buildInfo.getName() + ".v" + buildInfo.getVersion() + " from " + buildInfo.getDate();
            log.info("PT AI EE integration server build info: {}", buildInfoText);

            ComponentsStatus statuses = client.getDiagnosticApi().getStatus();
            String statusText = "PT AI: " + statuses.getPtai() + "; EMBEDDED: " + statuses.getEmbedded();
            log.info("PT AI EE components status: {}", statusText);
            return (statuses.getPtai().equals(FAILURE) || statuses.getEmbedded().equals(FAILURE)) ? 1 : 0;
        } catch (Exception e) {
            processApiException("Server check", e, verbose);
            return 1;
        }
    }
}
