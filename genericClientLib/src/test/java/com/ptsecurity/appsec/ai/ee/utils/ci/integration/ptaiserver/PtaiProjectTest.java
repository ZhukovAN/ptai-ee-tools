package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicyVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import org.junit.jupiter.api.Test;

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
            JsonSettings settings = JsonSettingsVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.1.json"))));
            JsonPolicy policy[] = JsonPolicyVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\policy\\policy.1.json"))));

            System.out.println(ptai.createProject(settings, policy));
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

            ptai.setUrl("https://127.0.0.1:30443");
            ptai.setCaCertsPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ca.chain.pem.crt"))));
            ptai.setKeyPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ssl.client.brief.pem"))));
            ptai.setKeyPassword("P@ssw0rd");
            String token = ptai.init();
            assertNotNull(token);
            System.out.println(token);
            // ptai.setName("JUnit.01");
            ptai.setName("TEST");
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
            ptai.upload(transfers, "src\\test\\resources\\src\\app01");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}