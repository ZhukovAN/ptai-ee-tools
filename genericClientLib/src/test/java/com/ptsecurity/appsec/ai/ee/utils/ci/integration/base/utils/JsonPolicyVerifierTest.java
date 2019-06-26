package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class JsonPolicyVerifierTest {

    @Test
    void verify() {
        try {
            JsonPolicyVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\policy\\policy.1.json"))));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}