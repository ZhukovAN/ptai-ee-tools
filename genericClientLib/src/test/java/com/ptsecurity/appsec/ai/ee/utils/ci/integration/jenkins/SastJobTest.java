package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.PtaiResultStatus;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class SastJobTest {
    private final static String ip = "127.0.0.1";
    @Test
    void execute() {
        SastJob sast = new SastJob();
        sast.setVerbose(true);
        sast.setLog(System.out);
        sast.setJobName("SAST/UI-managed SAST pipeline");
        sast.setUrl("http://" + ip + ":38080/jenkins");
        sast.setUserName("svc_ptai");
        sast.setToken("117872cd3acb073940e7280b34426a47c8");
        sast.setProjectName("JUnit.01");
        sast.setNodeName("PTAI");
        try {
            sast.init();
            PtaiResultStatus status = sast.execute(Files.createTempDirectory("PT_").toString());
        } catch (JenkinsClientException | IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    void executeSsl() {
        try {
            SastJob sast = new SastJob();
            sast.setVerbose(true);
            sast.setLog(System.out);
            sast.setJobName("SAST/UI-managed SAST pipeline");
            sast.setUrl("https://" + ip + ":38443/jenkins");
            // sast.setCaCertsPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keystores\\CB5352E43AC14295\\ca.chain.pem.crt"))));
            sast.setTrustStoreFile("src\\test\\resources\\keystores\\trust.p12");
            sast.setTrustStoreType("PKCS12");

            sast.setUserName("svc_ptai");
            sast.setPassword("P@ssw0rd");

            sast.setProjectName("JUnit.01");
            sast.setNodeName("LOCAL");

            sast.init();
            PtaiResultStatus status = sast.execute(Files.createTempDirectory("PT_").toString());
        } catch (JenkinsClientException | IOException e) {
            e.printStackTrace();
        }
    }
}