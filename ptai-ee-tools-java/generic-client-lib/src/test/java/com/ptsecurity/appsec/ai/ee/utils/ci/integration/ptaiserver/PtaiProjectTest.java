package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicyVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class PtaiProjectTest {
    @Test
    void createDeleteProject() {
        PtaiProject ptai = new PtaiProject();
        try {
            ptai.setVerbose(true);
            ptai.setConsoleLog(System.out);

            ptai.setUrl("https://127.0.0.1:30443");
            ptai.setCaCertsPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ca.chain.pem.crt"))));
            ptai.setKeyPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ssl.client.brief.pem"))));
            ptai.setKeyPassword("P@ssw0rd");
            String token = ptai.init();
            assertNotNull(token);
            System.out.println(token);
            ScanSettings settings = JsonSettingsVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.1.json"))));
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