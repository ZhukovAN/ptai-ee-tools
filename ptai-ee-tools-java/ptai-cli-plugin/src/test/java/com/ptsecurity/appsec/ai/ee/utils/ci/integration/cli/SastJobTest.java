package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class SastJobTest {
    @TempDir
    protected static File TEMPFOLDER;

    protected static Path KEYSTORE = null;
    protected static Path TRUSTSTORE = null;
    protected static ScanSettings SETTINGS;
    protected static Policy[] POLICY;

    protected static final String PTAIURL = "https://ptai.domain.org:8443/";



    @BeforeAll
    public static void init() throws URISyntaxException, IOException {
        KEYSTORE = Paths.get(SastJobTest.class.getClassLoader().getResource("keys/private.p12").toURI());
        TRUSTSTORE = Paths.get(SastJobTest.class.getClassLoader().getResource("keys/trust.jks").toURI());

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);

        Path json = Paths.get(SastJobTest.class.getClassLoader().getResource("json/policy.json").toURI());
        String jsonData = new String(Files.readAllBytes(json), StandardCharsets.UTF_8);
        POLICY = jsonMapper.readValue(jsonData, Policy[].class);

        json = Paths.get(SastJobTest.class.getClassLoader().getResource("json/settings.aiproj").toURI());
        jsonData = new String(Files.readAllBytes(json), StandardCharsets.UTF_8);
        SETTINGS = jsonMapper.readValue(jsonData, ScanSettings.class);
    }

    @BeforeEach
    public void pre() throws IOException {
        unzipTestSources(TEMPFOLDER.toPath().resolve("src"));
    }

    @AfterEach
    public void post() throws IOException {
        FileUtils.cleanDirectory(TEMPFOLDER);
    }

    void unzipTestSources(final Path destination) throws IOException {
        File zip = new File(getClass().getClassLoader().getResource("src/app01.zip").getFile());
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zip));
        ZipEntry entry = zis.getNextEntry();
        while (null != entry) {
            if (!entry.isDirectory()) {
                File out = new File(destination.resolve(entry.getName()).toString());
                out.getParentFile().mkdirs();
                OutputStream fos = new FileOutputStream(out);
                IOUtils.copy(zis, fos);
                fos.close();
            }
            entry = zis.getNextEntry();
        }
    }

    @Test
    void executeSlimWithUi() throws MalformedURLException {
        SlimSastJob job = SlimSastJob.builder()
                .url(new URL(PTAIURL))
                .project("APP01")
                .input(TEMPFOLDER.toPath().resolve("src"))
                .node("PTAI")
                .username("admin")
                .token("vFhjAhg6T0M6J2LZmselC63QOsM66GJO")
                .output(TEMPFOLDER.toPath().resolve(".ptai"))
                .clientId(Plugin.CLIENT_ID)
                .clientSecret(Plugin.CLIENT_SECRET)
                .includes("**/*")
                .excludes("**/*.js **/*.cs*")
                .truststore(TRUSTSTORE)
                .truststoreType("JKS")
                .truststorePassword("P@ssw0rd")
                .build();
        job.setConsoleLog(System.out);
        job.setLogPrefix(null);
        job.setVerbose(true);
        Assertions.assertTrue(PtaiResultStatus.FAILURE.equals(PtaiResultStatus.convert(job.execute())));
    }

    @Test
    void executeSlimWithJson() throws MalformedURLException {
        String projectName = "JUNIT-" + UUID.randomUUID().toString();
        SETTINGS.setProjectName(projectName);
        SlimSastJob job = SlimSastJob.builder()
                .url(new URL(PTAIURL))
                .project("APP01")
                .input(TEMPFOLDER.toPath().resolve("src"))
                .node("PTAI")
                .username("admin")
                .token("vFhjAhg6T0M6J2LZmselC63QOsM66GJO")
                .output(TEMPFOLDER.toPath().resolve(".ptai"))
                .clientId(Plugin.CLIENT_ID)
                .clientSecret(Plugin.CLIENT_SECRET)
                .includes("**/*")
                .excludes("**/*.js **/*.cs*")
                .truststore(TRUSTSTORE)
                .truststoreType("JKS")
                .truststorePassword("P@ssw0rd")
                .jsonSettings(SETTINGS)
                .jsonPolicy(POLICY)
                .build();
        job.setConsoleLog(System.out);
        job.setLogPrefix(null);
        job.setVerbose(true);
        Assertions.assertTrue(PtaiResultStatus.FAILURE.equals(PtaiResultStatus.convert(job.execute())));
    }

    @Test
    void executeWithJson() throws MalformedURLException {
        LegacySastJob job = LegacySastJob.builder()
                .jenkinsUrl(new URL("http://127.0.0.1:38080/jenkins"))
                .ptaiUrl(new URL("https://127.0.0.1:30443"))
                .project("JUNIT")
                .sastJob("SAST/UI-managed SAST pipeline")
                .node("PTAI")
                .keystore(KEYSTORE)
                .keystorePass("P@ssw0rd")
                .keystoreType("PKCS12")
                .truststore(TRUSTSTORE)
                .truststorePass("")
                .truststoreType("JKS")
                .username("svc_ptai")
                .password("P@ssw0rd")
                .includes("**/*")
                .excludes("target/** .*")
                .output(TEMPFOLDER.toPath()).build();
        job.execute();
    }
    /*
    @Test
    void execute() {
        try {
            LegacySastJob.execute(new String[]{
                    "--jenkins-url=http://127.0.0.1:38080/jenkins",
                    "--keystore=..\\genericClientLib\\src\\test\\resources\\keys\\private.p12",
                    "--keystore-pass=P@ssw0rd",
                    "--keystore-type=PKCS12",
                    "--node=PTAI",
                    "--token=\"P@ssw0rd\"",
                    "--ptai-project=JUnit.01",
                    "--ptai-url=https://127.0.0.1:30443",
                    "--sast-job=SAST/UI-managed SAST pipeline",
                    "--folder=..\\genericClientLib\\src\\test\\resources\\src\\app01",
                    "--excludes=\"" + "target/**, sast.report.*" + "\"",
                    "--truststore=..\\genericClientLib\\src\\test\\resources\\keys\\trust.jks",
                    "--truststore-type=JKS",
                    "--truststore-pass=\"\"",
                    "--username=svc_ptai",
                    "--verbose"
            });
        } catch (Exception e) {
            e.printStackTrace();
        }

    }*/
    @Test
    public void testJsonSerailization() throws JsonProcessingException {
        Policy[] jsonPolicy = null;
        String policy = new ObjectMapper().writeValueAsString(jsonPolicy);
        System.out.println(policy);
    }

    @Test
    public void testUrlNormalization() throws MalformedURLException, URISyntaxException {
        String url = "http://ptai.domain.org:8443/";
        url = new URL(url).toURI().normalize().toString();
        System.out.println(url);
    }

    @Test
    public void testPathRelative() {
        Path file = Paths.get("C:\\DATA\\TEMP\\20200430\\APP01\\BIN\\app01.war");
        Path parent = Paths.get("C:\\DATA\\TEMP\\20200430\\APP01");
        System.out.println(file.getFileName().toString());
        System.out.println(file.toFile().toURI().normalize());
        System.out.println(parent.relativize(file));
        System.out.println(file.relativize(parent));
    }
}