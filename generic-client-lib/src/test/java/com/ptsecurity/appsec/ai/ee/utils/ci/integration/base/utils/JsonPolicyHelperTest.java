package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonPolicyHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Check JSON policy helper")
class JsonPolicyHelperTest {

    @Test
    @DisplayName("Parse correct JSON policy file")
    void parseCorrectJsonPolicy() {
        Assertions.assertDoesNotThrow(() -> {
            String policy = TestUtils.getTextFromResources("json/policy", "policy.json");
            JsonPolicyHelper.verify(policy);
        });
    }
}