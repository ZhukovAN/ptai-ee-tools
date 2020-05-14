package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import org.junit.jupiter.api.Test;

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