package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.commands.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.google.common.net.HostAndPort;
import com.orbitz.consul.AclClient;
import com.orbitz.consul.Consul;
import com.orbitz.consul.KeyValueClient;
import com.orbitz.consul.model.acl.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import org.apache.commons.configuration2.INIConfiguration;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import picocli.CommandLine;

import java.io.*;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.stream.Stream;

/**
 * Command accepts two PKCS#12 key containers and their passwords, PT AI server URL,
 * embedded CI API token for svc_ptai user. Then it generates JKS keystore, saves keys
 * with randomly generated passwords using hardcoded "client" and "server", aliases ,
 * adds internal JWT token signing certificate with hardcoded "jwt" alias and again
 * randomly generated password. Then it adds all the certificates in PKCS#12 chains
 * as trusted ones and also all the certificates from
 * additional PEM- or P7B file. All these trusted certificates use randomly generated
 * aliases as we do not need to distinguish them. Also CA chain for server certificate
 * is being saved to PEM file to be used in plugins.
 * Then YML-config is stored in the Consul. Command uses
 * CONSUL/CONFIGFILE parameter from install.ini file to get path to serverConfig.json
 * file that stores master Consul API token. Command also generates required policies
 * and API token. API token can't be saved in Consul so command saves it in
 * boostrap.yml file
 */
@Log4j2
@CommandLine.Command(
        name = "service-config",
        sortOptions = false,
        exitCodeOnInvalidInput = 1000,
        exitCodeListHeading = "Exit Codes:%n",
        exitCodeList = {
                "0:Success",
                "1:Failure",
                "1000:Invalid input"},
        description = "Initializes PT AI integration service settings")
public class ServiceConfigure implements Callable<Integer> {
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    @Getter
    public static class ConsulConfig {
        @JsonIgnoreProperties(ignoreUnknown = true)
        @Getter
        public static class Tokens {
            @JsonProperty("master")
            @Getter
            protected String master;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        @Getter
        public static class Acl {
            @JsonProperty("tokens")
            protected Tokens tokens;
        }

        @JsonProperty("acl")
        @Getter
        protected Acl acl;
    }

    @Getter
    @Setter
    static class YamlConfig {
        @Getter
        @Setter
        static class Server {
            @Getter
            @Setter
            static class Ssl {
                @JsonProperty("key-password")
                private String keyPassword;
                @JsonProperty("key-store-password")
                private String keyStorePassword;
                @JsonProperty("trust-store-password")
                private String trustStorePassword;
            }
            private Ssl ssl = new Ssl();
        }
        private Server server = new Server();

        @Getter
        @Setter
        static class PtaiBackendServices {
            @JsonProperty("ci-url")
            private String ciUrl;
            @JsonProperty("ci-api-token")
            private String ciApiToken;
            @JsonProperty("ptai-url")
            private String ptaiUrl;
            @JsonProperty("ptai-key-password")
            private String ptaiKeyPassword;
        }

        @JsonProperty("ptai-backend-services")
        private PtaiBackendServices ptaiBackendServices = new PtaiBackendServices();

        @Getter
        @Setter
        static class PtaiAuthorizationServer {
            @JsonProperty("sign-key-password")
            private String signKeyPassword;
        }

        @JsonProperty("ptai-authorization-server")
        private PtaiAuthorizationServer ptaiAuthorizationServer = new PtaiAuthorizationServer();
    }

    @Getter
    @Setter
    static class BootstrapYamlConfig {
        @Getter
        @Setter
        static class Spring {
            @Getter
            @Setter
            static class Cloud {
                @Getter
                @Setter
                static class Consul {
                    @JsonProperty("token")
                    private String token;
                }
                @JsonProperty("consul")
                private Consul consul = new Consul();
            }
            @JsonProperty("cloud")
            private Cloud cloud = new Cloud();
        }
        @JsonProperty("spring")
        private Spring spring = new Spring();
    }

    private static final String SERVER_ALIAS = "server";
    private static final String CLIENT_ALIAS = "client";
    private static final String JWT_ALIAS = "jwt";
    private static final String JWT_PASSWORD = "79cb3692-ad20-4346-873c-95c4c306f642";
    private static final String JWT_KEY_PASSWORD = "a8abccde-2897-442a-98a0-0c7d63a5ddd7";

    @CommandLine.Option(
            names = {"-u", "--ptai-url"},
            required = true, order = 1,
            paramLabel = "<url>",
            description = "PT AI server URL, i.e. https://ptai.domain.org:443")
    private URL ptaiUrl;

    @CommandLine.Option(
            names = {"--server-keyfile"},
            required = true, order = 2,
            paramLabel = "<path>",
            description = "PT AI integration service private key PKCS#12 container file")
    private Path serverKeyFile;

    @CommandLine.Option(
            names = {"--server-keyfile-password"},
            required = false, order = 3,
            paramLabel = "<password>",
            description = "PT AI integration service private key container password")
    private String serverKeyFilePassword = "";

    @CommandLine.Option(
            names = {"--server-key-password"},
            required = false, order = 4,
            paramLabel = "<password>",
            description = "PT AI integration service private key password")
    private String serverKeyPassword = "";

    @CommandLine.Option(
            names = {"--client-keyfile"},
            required = true, order = 5,
            paramLabel = "<path>",
            description = "PT AI client authentication private key PKCS#12 container file")
    private Path clientKeyFile;

    @CommandLine.Option(
            names = {"--client-keyfile-password"},
            required = false, order = 6,
            paramLabel = "<password>",
            description = "PT AI client authentication private key container password")
    private String clientKeyFilePassword = "";

    @CommandLine.Option(
            names = {"--client-key-password"},
            required = false, order = 7,
            paramLabel = "<password>",
            description = "PT AI client authentication private key password")
    private String clientKeyPassword = "";

    @CommandLine.Option(
            names = {"--cert-file"},
            required = false, order = 8,
            paramLabel = "<path>",
            description = "Additional trusted certificates file. P7B and Base64-encoded PEM formats are supported")
    private Path certFile = null;

    @CommandLine.Option(
            names = {"--ci-url"},
            required = true, order = 9,
            paramLabel = "<url>",
            description = "PT AI embedded CI server URL, i.e. https://ci.domain.org:443")
    private URL ciUrl;

    @CommandLine.Option(
            names = {"--ci-token"},
            required = true, order = 10,
            paramLabel = "<token>",
            description = "PT AI embedded CI server's svc_ptai user API token")
    private String ciToken;

    @CommandLine.Option(
            names = {"--master-token"},
            required = false, order = 11,
            paramLabel = "<token>",
            description = "PT AI Consul's master token (see acl:token:master field in serverConfig.json file)")
    private String masterToken = null;

    @CommandLine.Option(
            names = {"--ini-file"},
            required = false, order = 12,
            paramLabel = "<path>",
            description = "Path to PT AI integration service $INSTDIR/bin/install.ini file")
    private Path iniFile = Paths.get(System.getProperty("user.dir")).resolve("bin").resolve("install.ini");

    @CommandLine.Option(
            names = {"--jar-file"},
            required = true, order = 13,
            paramLabel = "<path>",
            description = "Path to PT AI integration service JAR file")
    private Path jarFile = null;

    public static class InvalidConsulConfigFileException extends RuntimeException {
        public InvalidConsulConfigFileException() {
            super("Invalid Consul configuration file: acl.tokens.master is missing");
        }
    }

    protected static final String TOKEN_DESCRIPTION = "Token for service: integrationService";

    protected static final HostAndPort CONSUL_HOST_AND_PORT = HostAndPort.fromParts("localhost", 8500);

    public Integer call() throws Exception {
        try {
            // Set user-passed values in YAML config
            YamlConfig yamlConfig = new YamlConfig();
            yamlConfig.getPtaiBackendServices().setPtaiUrl(ptaiUrl.toString());
            yamlConfig.getPtaiBackendServices().setCiUrl(ciUrl.toString());
            yamlConfig.getPtaiBackendServices().setCiApiToken(ciToken);
            // Get Consul master token. If user haven't defined it directly, he may
            // passed us path to install.ini file that contains path to AI's Consul
            // serverConfig.json file with master token
            if (StringUtils.isEmpty(masterToken)) {
                if (!iniFile.toFile().exists()) {
                    log.error("File {} not found", iniFile.toString());
                    return 1000;
                }

                INIConfiguration ini = new Configurations().ini(iniFile.toFile());
                String consulConfigFilePath = ini.getSection("CONSUL").get(String.class, "CONFIGFILE");
                // Read Consul configuration (all we need is master token)
                String json = IOUtils.toString(
                        new FileInputStream(Paths.get(consulConfigFilePath).toFile()),
                        StandardCharsets.UTF_8);
                ObjectMapper mapper = new ObjectMapper();
                mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
                ConsulConfig consulConfig = mapper.readValue(json, ConsulConfig.class);
                masterToken = Optional.ofNullable(consulConfig)
                        .map(ConsulConfig::getAcl)
                        .map(ConsulConfig.Acl::getTokens)
                        .map(ConsulConfig.Tokens::getMaster)
                        .orElseThrow(InvalidConsulConfigFileException::new);
                log.info("Consul master token obtained");
            }

            // Create new in-memory keystore with random password
            String keystorePass = UUID.randomUUID().toString();
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(null, keystorePass.toCharArray());
            yamlConfig.getServer().getSsl().setKeyStorePassword(keystorePass);
            yamlConfig.getServer().getSsl().setTrustStorePassword(keystorePass);
            // Now we need to add keys from PKCS#12 containers and trusted certificates
            log.info("Keystore password {}", keystorePass);

            // Set of certificates to check for duplicates
            Set<Certificate> certificates = new HashSet<>();
            // Import server key
            String serverKeyPass = UUID.randomUUID().toString();
            importPkcs12Items(keystore, SERVER_ALIAS, serverKeyFile, serverKeyFilePassword, serverKeyPassword, serverKeyPass, certificates);
            yamlConfig.getServer().getSsl().setKeyPassword(serverKeyPass);
            log.info("Server private key password {}", serverKeyPass);

            // Import client key
            String clientKeyPass = UUID.randomUUID().toString();
            importPkcs12Items(keystore, CLIENT_ALIAS, clientKeyFile, clientKeyFilePassword, clientKeyPassword, clientKeyPass, certificates);
            yamlConfig.getPtaiBackendServices().setPtaiKeyPassword(clientKeyPass);
            log.info("Client private key password {}", clientKeyPass);

            // Import hardcoded JWT key
            String jwtKeyPass = UUID.randomUUID().toString();
            InputStream jwt = getClass().getClassLoader().getResourceAsStream("jwt.p12");
            importPkcs12Items(keystore, JWT_ALIAS, jwt, JWT_PASSWORD, JWT_KEY_PASSWORD, jwtKeyPass, certificates);
            yamlConfig.getPtaiAuthorizationServer().setSignKeyPassword(jwtKeyPass);
            log.info("JWT private key password {}", jwtKeyPass);

            // Import additional certificates
            if (null != certFile)
                importCertificates(certFile, certificates);

            // Add all certificates as trusted
            for (Certificate certificate : certificates)
                keystore.setCertificateEntry(UUID.randomUUID().toString(), certificate);

            String yaml = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)).writeValueAsString(yamlConfig);
            log.info("YAML configuration:");
            log.info(yaml);

            // Connect to Consul
            Consul client = Consul.builder()
                    .withHostAndPort(CONSUL_HOST_AND_PORT)
                    .withAclToken(masterToken)
                    .withReadTimeoutMillis(Duration.ofSeconds(2).toMillis())
                    .build();
            log.info("Consul connection established");
            AclClient aclClient = client.aclClient();

            Map<String, String> existingPolicies = new HashMap<>();
            aclClient.listPolicies().stream()
                    .forEach(p -> existingPolicies.put(p.name(), p.id()));
            aclClient.listTokens().stream()
                    .filter(t -> t.description().equalsIgnoreCase(TOKEN_DESCRIPTION))
                    .forEach(t -> aclClient.deleteToken(t.accessorId()));

            ImmutableToken.Builder tokenBuilder = ImmutableToken.builder();

            URI policyRules = ServiceConfigure.class.getClassLoader().getResource("policy").toURI();
            log.trace("Policy rules are in {}", policyRules);
            Path policyRulesContainer;
            if (policyRules.getScheme().equals("jar")) {
                java.nio.file.FileSystem fileSystem = FileSystems.newFileSystem(policyRules, Collections.<String, Object>emptyMap());
                fileSystem.getRootDirectories().forEach(d -> log.info("Directory {}", d.toString()));
                policyRulesContainer = fileSystem.getPath("/policy");
            } else
                policyRulesContainer = Paths.get(policyRules);

            Stream<Path> rules = Files.walk(policyRulesContainer, 1).skip(1);
            for (Iterator<Path> it = rules.iterator() ; it.hasNext() ; ) {
                Path rule = it.next();
                log.info("Rule {}", rule.toString());
                String name = rule.getName(rule.getNameCount() - 1).toString().replace(".hcl", "");
                if (existingPolicies.containsKey(name)) {
                    aclClient.deletePolicy(existingPolicies.get(name));
                    log.warn("Deleted existing Consul policy {}", name);
                }
                String ruleHcl = new String(Files.readAllBytes(rule));
                ImmutablePolicy policy = ImmutablePolicy.builder()
                        .name(name)
                        .rules(ruleHcl)
                        .build();
                PolicyResponse response = aclClient.createPolicy(policy);
                tokenBuilder.addPolicies(ImmutablePolicyLink.builder().id(response.id()).build());
                log.info("Created Consul policy {}", name);
            };

            tokenBuilder.description(TOKEN_DESCRIPTION).local(false);
            TokenResponse createdToken = aclClient.createToken(tokenBuilder.build());
            log.info("Created Consul token {}", createdToken.secretId());
            String consulToken = createdToken.secretId();

            KeyValueClient keyValueClient = client.keyValueClient();
            keyValueClient.putValue("services/integrationService/data", yaml);

            replaceFilesInJar(jarFile, createdToken.secretId(), keystore, keystorePass);
            return 0;
        } catch (Exception e) {
            log.error(e.getMessage());
            log.trace("Error details", e);
            return 1;
        }
    }

    /**
     * Method replaces file in JAR
     * @param jarPath JAR file with contents to be replaced
     * @param token Consul token
     * @param keystore JKS key/truststore file
     */
    protected static void replaceFilesInJar(
            @NonNull Path jarPath,
            @NonNull String token,
            @NonNull KeyStore keystore, @NonNull String keystorePass) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        final String KEYSTORE_ENTRY = "BOOT-INF/classes/keys/keystore.jks";
        final String BOOTSTRAP_ENTRY = "BOOT-INF/classes/bootstrap-prod.yml";
        ZipFile zip = new ZipFile(jarPath.toFile());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        keystore.store(outputStream, keystorePass.toCharArray());
        if (zip.getFileHeaders().stream().anyMatch(fh -> fh.getFileName().equalsIgnoreCase(KEYSTORE_ENTRY)))
            zip.removeFile(KEYSTORE_ENTRY);
        ZipParameters zp = new ZipParameters();
        zp.setFileNameInZip(KEYSTORE_ENTRY);
        zip.addStream(new ByteArrayInputStream(outputStream.toByteArray()), zp);
        log.trace("Keystore saved to JAR");

        outputStream = new ByteArrayOutputStream();
        BootstrapYamlConfig config = new BootstrapYamlConfig();
        config.getSpring().getCloud().getConsul().setToken(token);
        String yaml = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)).writeValueAsString(config);
        IOUtils.write(yaml, outputStream, StandardCharsets.UTF_8);
        zp.setFileNameInZip(BOOTSTRAP_ENTRY);
        if (zip.getFileHeaders().stream().anyMatch(fh -> fh.getFileName().equalsIgnoreCase(BOOTSTRAP_ENTRY)))
            zip.removeFile(BOOTSTRAP_ENTRY);
        zip.addStream(new ByteArrayInputStream(outputStream.toByteArray()), zp);
        log.trace("bootstrap-prod.yml saved to JAR");
    }

    public static Certificate importPkcs12Items(
            @NonNull KeyStore keystore, @NonNull String keyAlias,
            @NonNull Path container, @NonNull String containerPassword, @NonNull String keyPassword,
            @NonNull String newKeyPassword, Set<Certificate> certificates) throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return importPkcs12Items(keystore, keyAlias, new FileInputStream(container.toFile()), containerPassword, keyPassword, newKeyPassword, certificates);
    }

    public static Certificate importPkcs12Items(
            @NonNull KeyStore keystore, @NonNull String keyAlias,
            @NonNull InputStream container, @NonNull String containerPassword, @NonNull String keyPassword,
            @NonNull String newKeyPassword, Set<Certificate> certificates) throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Certificate res = null;

        log.trace("Trying to open key container");
        // BouncyCastle doesn't support different passwords for PKCS#12 container and private key
        // inside it
        // KeyStore pkcs12 = KeyStore.getInstance("PKCS12", "BC");
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
        pkcs12.load(container, containerPassword.toCharArray());
        log.trace("Key container opened, let's enumerate entities");

        Enumeration<String> aliases = pkcs12.aliases();
        boolean keyAdded = false;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!keyAdded && pkcs12.isKeyEntry(alias)) {
                log.trace("Private key {} found", alias);
                keyAdded = true;
                Key key = pkcs12.getKey(alias, keyPassword.toCharArray());
                Certificate[] chain = pkcs12.getCertificateChain(alias);

                // Prepare to save server certificate's CA chain to PEM file
                StringWriter stringWriter = null;
                JcaPEMWriter pemWriter = null;
                if (SERVER_ALIAS.equalsIgnoreCase(keyAlias)) {
                    stringWriter = new StringWriter();
                    pemWriter = new JcaPEMWriter(stringWriter);
                }

                // Let's add PKCS#12 certificates as a trusted ones. If chain has more than
                // one certificate - add only issuer's certificates. If there's only one
                // certificate in chain - no need to add it one more time
                if (1 < chain.length) {
                    for (int i = 1 ; i < chain.length ; i++) {
                        if (null == findCertificate(certificates, chain[i]))
                            certificates.add(chain[i]);
                        if (null != pemWriter)
                            pemWriter.writeObject(chain[i]);
                    }
                }
                if (null != pemWriter) {
                    pemWriter.flush();
                    pemWriter.close();
                    log.info("Server certificate CA chain {}", stringWriter.toString());
                }
                keystore.setKeyEntry(keyAlias, key, newKeyPassword.toCharArray(), chain);
                res = chain[0];
            } else if (pkcs12.isCertificateEntry(alias)) {
                Certificate certificate = pkcs12.getCertificate(alias);
                if (null == findCertificate(certificates, certificate))
                    certificates.add(certificate);
            }
        }
        return res;
    }

    /**
     * Method searches for certificate in the collection. Not sure if we can use generic search methods, streams etc
     * so will implement manual search
     * @param certificates Certificates collection
     * @param certificate Certificate to search
     * @return
     */
    public static Certificate findCertificate(@NonNull Collection<Certificate> certificates, @NonNull Certificate certificate) {
        for (Certificate c : certificates)
            if (c.equals(certificate)) return c;
        return null;
    }

    public static void importCertificates(@NonNull final Path certFile, @NonNull Set<Certificate> certificates) throws CertificateException, NoSuchProviderException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        byte[] data = IOUtils.toByteArray(new FileInputStream(certFile.toFile()));
        // Try to parse certificates as Base64-encoded PEM
        Matcher match = BaseClient.parse.matcher(new String(data, StandardCharsets.ISO_8859_1));
        while (match.find()) {
            byte[] binaryContent = Base64.getMimeDecoder().decode(match.group(2));
            if (!"CERTIFICATE".equalsIgnoreCase(match.group(1))) continue;

            Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(binaryContent));
            if (null == findCertificate(certificates, certificate))
                certificates.add(certificate);
        }
        // Try to parse as P7B container
        Collection<? extends Certificate> p7b = cf.generateCertificates(new ByteArrayInputStream(data));
        p7b.stream().forEach(c -> {
            if (null == findCertificate(certificates, c)) certificates.add(c);
        });
    }
}
