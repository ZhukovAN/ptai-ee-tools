package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class PtaiProjectTest {

    @org.junit.jupiter.api.Test
    void searchProject() {
        PtaiProject ptai = new PtaiProject();
        try {
            ptai.setVerbose(true);
            ptai.setLog(System.out);

            ptai.setUrl("https://127.0.0.1:30443");
            ptai.setCaCertsPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keystores\\CB5352E43AC14295\\ca.chain.pem.crt"))));
            ptai.setKeyPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keystores\\CB5352E43AC14295\\ssl.client.brief.pem"))));
            ptai.setKeyPassword("P@ssw0rd");
            String token = ptai.init();
            assertNotNull(token);
            System.out.println(token);
            ptai.setName("JUnit.01");
            UUID project = ptai.searchProject();
            assertNotNull(project);
            System.out.println(project.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @org.junit.jupiter.api.Test
    void upload() {
        PtaiProject ptai = new PtaiProject();
        try {
            ptai.setVerbose(true);
            ptai.setLog(System.out);

            ptai.setUrl("https://127.0.0.1:30443");
            ptai.setKeyStoreFile("src\\test\\resources\\keystores\\CB5352E43AC14295\\private.p12");
            ptai.setKeyStoreType("PKCS12");
            ptai.setKeyStorePassword("P@ssw0rd");
            ptai.setTrustStoreFile("src\\test\\resources\\keystores\\trust.jks");
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