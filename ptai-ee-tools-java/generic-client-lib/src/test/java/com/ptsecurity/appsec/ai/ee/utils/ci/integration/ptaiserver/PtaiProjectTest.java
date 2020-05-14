package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.JSON;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicyVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PtaiProjectTest {

    protected static Path KEYSTORE = null;
    protected static Path TRUSTSTORE = null;

    @BeforeAll
    public static void init() throws URISyntaxException, IOException {
        KEYSTORE = Paths.get(PtaiProjectTest.class.getClassLoader().getResource("keys/keystore.jks").toURI());
        TRUSTSTORE = Paths.get(PtaiProjectTest.class.getClassLoader().getResource("keys/truststore.jks").toURI());
        /*
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        jsonMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);

        Path json = Paths.get(SastJobTest.class.getClassLoader().getResource("json/policy.json").toURI());
        String jsonData = new String(Files.readAllBytes(json), StandardCharsets.UTF_8);
        POLICY = jsonMapper.readValue(jsonData, Policy[].class);

        json = Paths.get(SastJobTest.class.getClassLoader().getResource("json/settings.aiproj").toURI());
        jsonData = new String(Files.readAllBytes(json), StandardCharsets.UTF_8);
        SETTINGS = jsonMapper.readValue(jsonData, ScanSettings.class);
         */
    }

    @Test
    void testProjectJsonParse() {
        String json = "{\"id\":\"daf66a5d-7108-42e0-bf79-c0bbbeb8cbd6\",\"creationDate\":\"2020-05-07T22:28:23.940864+03:00\",\"settingsId\":\"112f65ca-d914-457b-a7ac-3733a504794b\",\"name\":\"JUNIT-ef685e4f-67a6-4050-81ed-c3d47a96e8e0\",\"lastScanDate\":\"0001-01-01T00:00:00Z\",\"filePatterns\":null}";
        Project prj = new JSON().deserialize(json, Project.class);
        assertEquals(prj.getId().toString(), "daf66a5d-7108-42e0-bf79-c0bbbeb8cbd6");
    }

    @Test
    void createDeleteProject() {
        PtaiProject ptai = new PtaiProject();
        try {
            ptai.setVerbose(true);
            ptai.setConsoleLog(System.out);

            ptai.setUrl("https://ptai.domain.org:443");
            ptai.setKeyStoreFile(KEYSTORE.toString());
            ptai.setKeyStorePassword("P@ssw0rd");
            ptai.setTrustStoreFile(TRUSTSTORE.toString());
            ptai.setKeyAlias("ptai ssl client certificate");
            ptai.setKeyPassword("1q2w3e4r");
            String token = ptai.init();
            assertNotNull(token);
            System.out.println(token);
            ScanSettings settings = JsonSettingsVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.1.json"))));
            settings.setProjectName("JUNIT-" + UUID.randomUUID().toString());
            Policy policy[] = JsonPolicyVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\policy\\policy.1.json"))));

            System.out.println(ptai.createProject(settings));
            // ptai.deleteProject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    void searchProject() {
        PtaiProject ptai = new PtaiProject();
        try {
            ptai.setVerbose(true);
            ptai.setConsoleLog(System.out);

            // ptai.setUrl("https://127.0.0.1:30443");
            ptai.setUrl("https://ptaisrv.domain.org:443");
            // ptai.setUrl("https://10.0.214.10:443");
            ptai.setCaCertsPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ca.chain.pem.crt"))));
            ptai.setKeyPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ssl.client.brief.pem"))));
            ptai.setKeyPassword("P@ssw0rd");
            String token = ptai.init();
            assertNotNull(token);
            System.out.println(token);
            // ptai.setName("JUnit.01");
            ptai.setName("DEVEL.TEST.JAVA");
            UUID project = ptai.searchProject();
            assertNotNull(project);
            System.out.println(project.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    void upload() {
        PtaiProject ptai = new PtaiProject();
        try {
            ptai.setVerbose(true);
            ptai.setConsoleLog(System.out);

            ptai.setUrl("https://127.0.0.1:30443");
            ptai.setKeyStoreFile("src\\test\\resources\\keys\\private.p12");
            ptai.setKeyStoreType("PKCS12");
            ptai.setKeyStorePassword("P@ssw0rd");
            ptai.setTrustStoreFile("src\\test\\resources\\keys\\trust.jks");
            ptai.setTrustStoreType("JKS");
            ptai.setTrustStorePassword("");
            String token = ptai.init();
            assertNotNull(token);
            System.out.println(token);
            Transfers transfers = new Transfers();
            transfers.add(Transfer.builder().includes("**/*").excludes("target/** .settings/** .*").build());
            ptai.setName("JUnit.01");
            FileCollector collector = new FileCollector(transfers, null);
            File zip = FileCollector.collect(transfers, new File("src\\test\\resources\\src\\app01"), ptai);
            ptai.upload(zip);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}