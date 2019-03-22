package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class BaseTest {

    @Test
    void checkKey() {
        try {
            Base base = new Base();
            base.setUrl("http://127.0.0.1:8080");
            base.setKeyPem(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\keys\\ssl.client.brief.pem"))));
            base.setKeyPassword("P@ssw0rd");
            base.baseInit();
            System.out.println("BaseTest done");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}