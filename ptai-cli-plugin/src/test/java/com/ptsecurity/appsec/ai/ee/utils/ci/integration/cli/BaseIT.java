package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Tag("integration-legacy")
class BaseIT {
    /**
     * Temporal folder where three subfolders will be created: for
     * unzipped sources, for modified JSON-defined policy / scan settings
     * and for generated reports
     */
    @TempDir
    static File TEMP_FOLDER;
    /**
     * Temporal folder where test sources will be unziipped
     */
    static String SOURCES_FOLDER;
    /**
     * Temporal folder where reports will be generated
     */
    static String REPORT_FOLDER;
    /**
     * Temporal fodler where modified JSON-defined policy / scan settings will be saved
     */
    static String JSON_FOLDER;

    /**
     * Path to PEM file with CA certificate chain
     */
    static String PEM_PATH = null;

    static String SCAN_SETTINGS_PATH = null;
    static ScanSettings SCAN_SETTINGS;
    static String POLICY_PATH = null;
    static Policy[] POLICY;
    static Policy[] EMPTY_POLICY = new Policy[0];

    static String NEW_PROJECT;
    static final String EXISTING_PROJECT = "app01";

    // protected static final String TOKEN = "k+bwoHZBrpi+2TV7Ne25cbFeTXGn+idS";
    static final String TOKEN = "6M9Qsct5fg20/UEzN7/hvR2RlXkTWOI5";
    // protected static final String PTAI_URL = "https://10.0.216.109:443/";
    static final String PTAI_URL = "https://ptai.domain.org:443/";
    // protected static final String PEM_RESOURCE = "keys/pt.pem";
    static final String PEM_RESOURCE = "keys/domain.org.pem";

    @BeforeAll
    public static void init() throws IOException {
        SOURCES_FOLDER = TEMP_FOLDER.toPath().resolve("src").toString();
        REPORT_FOLDER = TEMP_FOLDER.toPath().resolve(".ptai").toString();
        JSON_FOLDER = TEMP_FOLDER.toPath().resolve("json").toString();

        PEM_PATH = getResourcePath(PEM_RESOURCE);

        SCAN_SETTINGS_PATH = getResourcePath("json/settings.aiproj");
        POLICY_PATH = getResourcePath("json/policy.json");
    }

    @SneakyThrows
    static String getResourcePath(@NonNull final String name) {
        return getResourceFile(name).toString();
    }

    @SneakyThrows
    static File getResourceFile(@NonNull final String name) {
        @NonNull URL url = BaseIT.class.getClassLoader().getResource(name);
        Assertions.assertNotNull(url);
        Assertions.assertNotNull(url.toURI());
        return Paths.get(url.toURI()).toFile();
    }

    @AfterAll
    public static void fini() {
    }

    @SneakyThrows
    @BeforeEach
    public void pre() {
        NEW_PROJECT = "junit-" + UUID.randomUUID().toString();
        unzipTestSources();

        String json = new String(Files.readAllBytes(Paths.get(SCAN_SETTINGS_PATH)), StandardCharsets.UTF_8);
        SCAN_SETTINGS = JsonSettingsHelper.verify(json);

        json = new String(Files.readAllBytes(Paths.get(POLICY_PATH)), StandardCharsets.UTF_8);
        POLICY = JsonPolicyHelper.verify(json);
    }

    @AfterEach
    public void post() throws IOException {
        FileUtils.cleanDirectory(TEMP_FOLDER);
    }

    @SneakyThrows
    private void unzipTestSources() {
        File zip = getResourceFile("code/app01.zip");
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zip));
        ZipEntry entry = zis.getNextEntry();
        while (null != entry) {
            if (!entry.isDirectory()) {
                File out = new File(Paths.get(SOURCES_FOLDER).resolve(entry.getName()).toString());
                out.getParentFile().mkdirs();
                OutputStream fos = new FileOutputStream(out);
                IOUtils.copy(zis, fos);
                fos.close();
            }
            entry = zis.getNextEntry();
        }
    }

    @SneakyThrows
    protected String saveScanSettings() {
        Path res = Paths.get(JSON_FOLDER).resolve(UUID.randomUUID().toString() + ".aiproj");
        String json = new ObjectMapper().writeValueAsString(SCAN_SETTINGS.fix());
        FileUtils.writeStringToFile(res.toFile(), json, StandardCharsets.UTF_8);
        return res.toString();
    }
}