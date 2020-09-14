package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class PtaiProjectIT {
    @TempDir
    protected static File TEMPFOLDER;
    protected static File TEMPSRCFOLDER;
    protected static File TEMPREPORTFOLDER;
    protected static File TEMPJSONFOLDER;

    protected static Path KEYSTORE_PATH = null;
    protected static Path TRUSTSTORE_PATH = null;
    protected static Path SETTINGS_PATH = null;
    protected static Path POLICY_PATH = null;
    protected static ScanSettings SETTINGS;
    protected static Policy[] POLICY;

    protected static final String NEW_PROJECT_NAME = "JUNIT-" + UUID.randomUUID().toString();

    protected static final String PTAIURL = "https://ptai.domain.org:443/";

    @BeforeAll
    public static void init() throws URISyntaxException, IOException {
        TEMPSRCFOLDER = TEMPFOLDER.toPath().resolve("src").toFile();
        TEMPREPORTFOLDER = TEMPFOLDER.toPath().resolve(".ptai").toFile();
        TEMPJSONFOLDER = TEMPFOLDER.toPath().resolve("json").toFile();

        KEYSTORE_PATH = Paths.get(PtaiProjectIT.class.getClassLoader().getResource("keys/keystore.jks").toURI());
        TRUSTSTORE_PATH = Paths.get(PtaiProjectIT.class.getClassLoader().getResource("keys/truststore.jks").toURI());

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);

        Path path = Paths.get(PtaiProjectIT.class.getClassLoader().getResource("json/policy.json").toURI());
        String jsonData = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        POLICY = jsonMapper.readValue(jsonData, Policy[].class);

        path = Paths.get(PtaiProjectIT.class.getClassLoader().getResource("json/settings.aiproj").toURI());
        jsonData = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        SETTINGS = jsonMapper.readValue(jsonData, ScanSettings.class);
    }

    @AfterAll
    public static void fini() {
    }

    @BeforeEach
    public void pre() throws IOException {
        unzipTestSources(TEMPSRCFOLDER.toPath());
        saveJsons();
    }

    @AfterEach
    public void post() throws IOException {
        FileUtils.cleanDirectory(TEMPFOLDER);
    }

    void unzipTestSources(final Path destination) throws IOException {
        File zip = new File(getClass().getClassLoader().getResource("code/app01.zip").getFile());
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

    static void saveJsons() throws IOException {
        SETTINGS_PATH = TEMPJSONFOLDER.toPath().resolve("settings.json");
        POLICY_PATH = TEMPJSONFOLDER.toPath().resolve("policy.json");
        String json = new ObjectMapper().writeValueAsString(SETTINGS.fix());
        FileUtils.writeStringToFile(SETTINGS_PATH.toFile(), json, StandardCharsets.UTF_8);
        json = new ObjectMapper().writeValueAsString(POLICY);
        FileUtils.writeStringToFile(POLICY_PATH.toFile(), json, StandardCharsets.UTF_8);
    }

    @Test
    void testCreateProject() throws IOException {
        SETTINGS.setProjectName(NEW_PROJECT_NAME);
        saveJsons();

        PtaiProject ptai = new PtaiProject();

        ptai.setVerbose(true);
        ptai.setConsole(System.out);

        ptai.setUrl(PTAIURL);
        ptai.setKeyStoreFile(KEYSTORE_PATH.toString());
        ptai.setKeyStorePassword("P@ssw0rd");
        ptai.setKeyAlias("ptai ssl client certificate");
        ptai.setKeyPassword("1q2w3e4r");

        ptai.setTrustStoreFile(TRUSTSTORE_PATH.toString());
        String token = ptai.init();
        Assertions.assertNotNull(token);
        ptai.createProject(SETTINGS);
    }
}