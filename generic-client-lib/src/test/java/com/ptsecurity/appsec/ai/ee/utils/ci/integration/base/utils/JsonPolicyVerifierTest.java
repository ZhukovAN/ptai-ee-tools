package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class JsonPolicyVerifierTest {

    @Test
    void verify() {
        try {
            String policy = TestUtils.getTextFromResources("json/policy", "policy.1.json");
            JsonPolicyVerifier.verify(policy);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}