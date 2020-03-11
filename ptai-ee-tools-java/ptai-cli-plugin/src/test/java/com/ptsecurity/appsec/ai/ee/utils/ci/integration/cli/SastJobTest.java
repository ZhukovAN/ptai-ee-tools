package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import org.junit.jupiter.api.Test;

class SastJobTest {
    @Test
    void executeWithJson() {
        try {
            Transfers transfers = new Transfers();
            transfers.add(Transfer.builder().includes("**/*").excludes("target/** .settings/** .*").build());
            ObjectMapper objectMapper = new ObjectMapper();
            String transfersJson = objectMapper.writeValueAsString(transfers);
            // transfersJson = "[{\"includes\":\"**/*\",\"excludes\":\"target/** .settings/** .*\"}]";

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
                    "--transfersJson=\"" + transfersJson + "\"",
                    "--truststore=..\\genericClientLib\\src\\test\\resources\\keys\\trust.jks",
                    "--truststore-type=JKS",
                    "--truststore-pass=\"\"",
                    "--username=svc_ptai",
                    "--verbose"
            });
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

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

    }
}