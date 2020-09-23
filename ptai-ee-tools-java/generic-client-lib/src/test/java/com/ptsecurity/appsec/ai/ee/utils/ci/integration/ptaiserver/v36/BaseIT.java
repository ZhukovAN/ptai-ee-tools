package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.reflect.TypeToken;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.ApiClient;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.auth.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanProgress;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ScanResult;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Stage;
import com.ptsecurity.appsec.ai.ee.ptai.server.scanscheduler.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.CertificateHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils.ProgrammingLanguageHelper;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;
import lombok.SneakyThrows;
import okhttp3.Call;
import okhttp3.Request;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class BaseIT {
    public static final String TEAMCITY_PLUGIN_API_TOKEN = "EviL0KKic2FplOuBGz6Ox98+JWkRbio4";
    public static final String JENKINS_PLUGIN_API_TOKEN = "xlk5Ug07ex7KQHcEodcm9IK5qKgO8brJ";
    public static final String PTAI_URL = "https://10.0.216.109";

    @TempDir
    protected static File TEMPFOLDER;
    protected static File TEMPSRCFOLDER;
    protected static File TEMPREPORTFOLDER;
    protected static File TEMPJSONFOLDER;

    protected static Path SETTINGS_PATH = null;
    protected static ScanSettings SETTINGS;
    protected static Path POLICY_PATH = null;
    protected static Policy[] POLICY;
    protected static Path TRUSTSTORE_PATH = null;
    protected static KeyStore TRUSTSTORE;

    protected BaseClient client = null;

    @SneakyThrows
    @BeforeAll
    public static void init() {
        TEMPSRCFOLDER = TEMPFOLDER.toPath().resolve("src").toFile();
        TEMPREPORTFOLDER = TEMPFOLDER.toPath().resolve(".ptai").toFile();
        TEMPJSONFOLDER = TEMPFOLDER.toPath().resolve("json").toFile();

        TRUSTSTORE_PATH = Paths.get(BaseIT.class.getClassLoader().getResource("keys/truststore.jks").toURI());
        TRUSTSTORE = KeyStore.getInstance("JKS");
        TRUSTSTORE.load(new FileInputStream(TRUSTSTORE_PATH.toFile()), "".toCharArray());

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

    @SneakyThrows
    @BeforeEach
    public void pre() {
        client = new BaseClient();
        client.setUrl(PTAI_URL);
        client.setToken(TEAMCITY_PLUGIN_API_TOKEN);
        client.setCaCertsPem(CertificateHelper.trustStoreToPem(TRUSTSTORE));
        client.init();

        unzipTestSources(TEMPSRCFOLDER.toPath());
        saveJsons();
    }

    @AfterEach
    public void post() throws IOException {
        FileUtils.cleanDirectory(TEMPFOLDER);
    }

    @SneakyThrows
    void unzipTestSources(final Path destination) {
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

    @SneakyThrows
    @Test
    public void testBricksProjectOperations() {
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient client = new com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient();
        client.setUrl("https://10.0.216.109");
        client.setToken(TEAMCITY_PLUGIN_API_TOKEN);
        client.setCaCertsPem(CertificateHelper.trustStoreToPem(TRUSTSTORE));
        client.init();

        LicenseApi licenseApi = client.getLicenseApi();
        ProjectsApi projectsApi = client.getProjectsApi();
        ScanApi scanApi = client.getScanApi();
        ScanAgentApi scanAgentApi = client.getScanAgentApi();

        EnterpriseLicenseData license = licenseApi.apiLicenseGet();
        System.out.println(license);

        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet(UUID.randomUUID().toString());
        // API returns null for missing project
        Assertions.assertNull(projectInfo);

        projectInfo = projectsApi.apiProjectsLightNameGet("bricks");
        Assertions.assertNotNull(projectInfo);
        System.out.println("Project ID is " + projectInfo.getId());

        // Project project = projectsApi.apiProjectsProjectIdGet(projectInfo.getId());

        StartScanModel startScanModel = new StartScanModel();
        startScanModel.setProjectId(projectInfo.getId());
        startScanModel.setScanType(ScanType.FULL);
        UUID scanResultId =  scanApi.apiScanStartPost(startScanModel);
        System.out.println("Scan result ID is " + scanResultId.toString());

        Stage stage = null;
        do {
            ScanResult scanResult = projectsApi.apiProjectsProjectIdScanResultsScanResultIdGet(projectInfo.getId(), scanResultId);
            System.out.println(scanResult);
            ScanProgress progress = scanResult.getProgress();
            stage = progress.getStage();
            Thread.sleep(500);
        } while (!Stage.DONE.equals(stage) && !Stage.ABORTED.equals(stage) && !Stage.FAILED.equals(stage));
    }

    @SneakyThrows
    @Test
    public void testProjectOperations() {
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient client = new com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient();
        client.setUrl("https://10.0.216.109");
        client.setToken(TEAMCITY_PLUGIN_API_TOKEN);
        client.setCaCertsPem(CertificateHelper.trustStoreToPem(TRUSTSTORE));
        client.init();

        LicenseApi licenseApi = client.getLicenseApi();
        ProjectsApi projectsApi = client.getProjectsApi();
        ScanApi scanApi = client.getScanApi();

        ProjectLight projectInfo = projectsApi.apiProjectsLightNameGet("bricks");
        // projectsApi.apiProjectsProjectIdScanResultsGet(projectInfo.getId(), AuthSc)
        StartScanModel startScanModel = new StartScanModel();
        startScanModel.setProjectId(projectInfo.getId());
        startScanModel.setScanType(ScanType.FULL);
        UUID scanResultId =  scanApi.apiScanStartPost(startScanModel);

        // Project project = projectsApi.apiProjectsProjectIdGet(projectInfo.getId());


        // EnterpriseLicenseData license = licenseApi.apiLicenseGet();
        // System.out.println(license);
    }

    @SneakyThrows
    @Test
    public void testApiTokenCreate() {
        String bearerToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiJTLTEtNS0yMS0xMDIzMTkxNzMwLTcyNzgyOTkyNy0zOTg1MDUwMTkyLTI3MjU5IiwiQXV0aFNjb3BlIjoiVmlld2VyIiwic3ViIjoiUy0xLTUtMjEtMTAyMzE5MTczMC03Mjc4Mjk5MjctMzk4NTA1MDE5Mi0yNzI1OSIsIm5iZiI6MTU5ODM2MTE4NiwiZXhwIjoxNTk4MzYxNDg2LCJpYXQiOjE1OTgzNjExODYsImlzcyI6IkFJLkVudGVycHJpc2UiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjUwMDY1LyJ9.1VbG54p6O71NK8rOSqiEp7PUQI8wJHqVSijac8sO-70";

        AccessTokenApi tokenApi = new AccessTokenApi(new ApiClient());
        tokenApi.getApiClient().setApiKeyPrefix("Bearer");
        tokenApi.getApiClient().setApiKey(bearerToken);

        BaseClient client = new BaseClient();
        client.setUrl("https://10.0.216.109");
        // client.setTrustStoreFile(TRUSTSTORE_PATH.toString());
        // client.setTrustStorePassword("");
        // client.baseInit();
        // client.initClients(tokenApi);

        OffsetDateTime tokenExpiration = OffsetDateTime.now().plusMonths(1);
        // Name field is unique: if you'll try to create multiple tokens that API error will be raised
        AccessTokenCreateModel tokenModel = new AccessTokenCreateModel()
                .name("ptai-jenkins-plugin")
                .expiresDateTime(tokenExpiration)
                .scopes(AccessTokenScopeType.LIGHTCLIENTANDPLUGINS);

        Call call = tokenApi.apiAuthAccessTokenCreatePostCall(tokenModel, null);
        Request request = call.request().newBuilder().header("Authorization", "Bearer " + bearerToken).build();
        call = tokenApi.getApiClient().getHttpClient().newCall(request);
        Type localVarReturnType = new TypeToken<String>(){}.getType();
        ApiResponse<String> response = tokenApi.getApiClient().execute(call, localVarReturnType);

        // Type localVarReturnType = new TypeToken<String>(){}.getType();
        // return localVarApiClient.execute(localVarCall, localVarReturnType);

        // call.
        String token = response.getData();
        System.out.println(token);
    }

    @SneakyThrows
    @Test
    public void testRefreshToken() {
        LicenseApi licenseApi = client.getLicenseApi();
        EnterpriseLicenseData licenseData = licenseApi.apiLicenseGet();
        System.out.println(licenseData);
        Thread.sleep(1000);
        licenseData = licenseApi.apiLicenseGet();
        System.out.println(licenseData);
        Thread.sleep(1000 * 60 * 15);
        licenseData = licenseApi.apiLicenseGet();
        System.out.println(licenseData);
    }

    @SneakyThrows
    @Test
    public void testLicenseData() {
        LicenseApi licenseApi = client.getLicenseApi();
        EnterpriseLicenseData licenseData = licenseApi.apiLicenseGet();
        System.out.println(licenseData);
        System.out.println(getLicenseData(licenseData));
    }

    public static String getLicenseData(@NonNull final EnterpriseLicenseData licenseData) {

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy");
        StringBuilder builder = new StringBuilder();
        builder
                .append("Start date: ")
                .append(formatter.format(licenseData.getStartDate()))
                .append(", expiration date: ")
                .append(formatter.format(licenseData.getEndDate()))
                .append(", projects: ")
                .append(licenseData.getLimitProjects());
        if (0 != licenseData.getLanguages().size()) {
            builder.append(", LANGUAGES: ");
            List<String> languageNames = licenseData.getLanguages().stream()
                    .map(l -> ProgrammingLanguageHelper.LANGUAGES.getOrDefault(l, ""))
                    .filter(l -> StringUtils.isNotEmpty(l))
                    .sorted().collect(Collectors.toList());
            String[] languageNamesArray = new String[languageNames.size()];
            languageNamesArray = languageNames.toArray(languageNamesArray);
            builder.append(String.join(", ", languageNamesArray));
        }
        return builder.toString();
    }
}
