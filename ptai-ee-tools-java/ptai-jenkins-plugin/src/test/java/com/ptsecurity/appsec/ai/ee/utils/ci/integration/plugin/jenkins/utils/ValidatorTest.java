package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ValidatorTest {

    @Test
    void doCheckFieldUrl() {
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