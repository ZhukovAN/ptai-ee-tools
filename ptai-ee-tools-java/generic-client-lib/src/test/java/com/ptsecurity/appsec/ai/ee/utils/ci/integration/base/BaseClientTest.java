package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

class BaseClientTest {

    @Test
    void checkKey() {
        try {
            BaseClient baseClient = new BaseClient();
            baseClient.setUrl("http://127.0.0.1:8080");
            baseClient.setKeyPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ssl.client.brief.pem"))));
            baseClient.setKeyPassword("P@ssw0rd");
            baseClient.baseInit();
            System.out.println("BaseClientTest done");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}