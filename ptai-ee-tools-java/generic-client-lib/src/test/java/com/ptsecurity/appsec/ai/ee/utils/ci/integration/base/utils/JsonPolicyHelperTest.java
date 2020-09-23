package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import org.junit.jupiter.api.Test;

class JsonPolicyHelperTest {

    @Test
    void verify() {
        try {
            String policy = TestUtils.getTextFromResources("json/policy", "policy.1.json");
            JsonPolicyHelper.verify(policy);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}