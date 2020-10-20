package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class BaseIT {
    @TempDir
    protected static File TEMP_FOLDER;
    protected static File TEMP_SOURCES_FOLDER;
    protected static File TEMP_REPORT_FOLDER;
    protected static File TEMP_JSON_FOLDER;

    protected static Path PEM_PATH = null;
    protected static Path SETTINGS_PATH = null;
    protected static Path POLICY_PATH = null;
    protected static Path EMPTY_POLICY_PATH = null;
    protected static Path REPORTS_JSON_PATH = null;
    protected static ScanSettings SETTINGS;
    protected static Policy[] POLICY;
    protected static Policy[] EMPTY_POLICY = new Policy[0];

    protected static final String NEW_PROJECT_NAME = "JUNIT-" + UUID.randomUUID().toString();
    protected static final String EXISTING_PROJECT_NAME = "app01";

    // protected static final String TOKEN = "k+bwoHZBrpi+2TV7Ne25cbFeTXGn+idS";
    protected static final String TOKEN = "6M9Qsct5fg20/UEzN7/hvR2RlXkTWOI5";
    // protected static final String PTAI_URL = "https://10.0.216.109:443/";
    protected static final String PTAI_URL = "https://ptai.domain.org:443/";
    // protected static final String PEM_RESOURCE = "keys/pt.pem";
    protected static final String PEM_RESOURCE = "keys/domain.org.pem";

    protected static final String REPORTS_JSON_RESOURCE = "json/reports.json";

    @BeforeAll
    public static void init() throws URISyntaxException, IOException {
        TEMP_SOURCES_FOLDER = TEMP_FOLDER.toPath().resolve("src").toFile();
        TEMP_REPORT_FOLDER = TEMP_FOLDER.toPath().resolve(".ptai").toFile();
        TEMP_JSON_FOLDER = TEMP_FOLDER.toPath().resolve("json").toFile();

        PEM_PATH = Paths.get(BaseIT.class.getClassLoader().getResource(PEM_RESOURCE).toURI());
        REPORTS_JSON_PATH = Paths.get(BaseIT.class.getClassLoader().getResource(REPORTS_JSON_RESOURCE).toURI());

        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);

        Path path = Paths.get(BaseIT.class.getClassLoader().getResource("json/policy.json").toURI());
        String jsonData = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        POLICY = jsonMapper.readValue(jsonData, Policy[].class);

        path = Paths.get(BaseIT.class.getClassLoader().getResource("json/settings.aiproj").toURI());
        jsonData = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        SETTINGS = jsonMapper.readValue(jsonData, ScanSettings.class);
    }

    @AfterAll
    public static void fini() {
    }

    @BeforeEach
    public void pre() throws IOException {
        unzipTestSources(TEMP_SOURCES_FOLDER.toPath());
        saveJsons();
    }

    @AfterEach
    public void post() throws IOException {
        FileUtils.cleanDirectory(TEMP_FOLDER);
    }

    protected void unzipTestSources(final Path destination) throws IOException {
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

    protected static void saveJsons() throws IOException {
        SETTINGS_PATH = TEMP_JSON_FOLDER.toPath().resolve("settings.json");
        POLICY_PATH = TEMP_JSON_FOLDER.toPath().resolve("policy.json");
        EMPTY_POLICY_PATH = TEMP_JSON_FOLDER.toPath().resolve("empty.policy.json");
        String json = new ObjectMapper().writeValueAsString(SETTINGS.fix());
        FileUtils.writeStringToFile(SETTINGS_PATH.toFile(), json, StandardCharsets.UTF_8);
        json = new ObjectMapper().writeValueAsString(POLICY);
        FileUtils.writeStringToFile(POLICY_PATH.toFile(), json, StandardCharsets.UTF_8);
        json = new ObjectMapper().writeValueAsString(EMPTY_POLICY);
        FileUtils.writeStringToFile(EMPTY_POLICY_PATH.toFile(), json, StandardCharsets.UTF_8);
    }
}