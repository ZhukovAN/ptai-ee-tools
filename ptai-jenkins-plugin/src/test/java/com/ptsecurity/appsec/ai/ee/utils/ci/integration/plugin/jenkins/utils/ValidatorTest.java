package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Check field values validator")
class ValidatorTest {

    @Test
    @DisplayName("Validate miscellaneous URL values")
    void checkFieldUrl() {
        assertTrue(Validator.doCheckFieldUrl("https://poc-ptai.domain.local:8443"));
        assertTrue(Validator.doCheckFieldUrl("https://192.168.0.1:8443"));
        assertTrue(Validator.doCheckFieldUrl("https://ptai.domain.local:8443"));
        assertTrue(Validator.doCheckFieldUrl("http://ptai.domain.org:8443"));
        assertTrue(Validator.doCheckFieldUrl("https://ptai.domain.org:8443"));
        assertTrue(Validator.doCheckFieldUrl("http://ptai.domain.local:8443"));
        assertTrue(Validator.doCheckFieldUrl("https://ptai.domain.local:8443"));
        assertFalse(Validator.doCheckFieldUrl("https://ast.ptai:8443"));
    }
}