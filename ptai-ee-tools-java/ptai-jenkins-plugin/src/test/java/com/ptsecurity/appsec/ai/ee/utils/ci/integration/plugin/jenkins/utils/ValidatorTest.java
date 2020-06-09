package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import org.apache.commons.validator.routines.UrlValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ValidatorTest {

    @Test
    void doCheckFieldUrl() {
        Assertions.assertTrue(Validator.doCheckFieldUrl("https://192.168.0.1:8443"));
        Assertions.assertTrue(Validator.doCheckFieldUrl("https://ptai.domain.local:8443"));
        Assertions.assertTrue(Validator.doCheckFieldUrl("http://ptai.domain.org:8443"));
        Assertions.assertTrue(Validator.doCheckFieldUrl("https://ptai.domain.org:8443"));
        Assertions.assertTrue(Validator.doCheckFieldUrl("http://ptai.domain.local:8443"));
        Assertions.assertTrue(Validator.doCheckFieldUrl("https://ptai.domain.local:8443"));
        Assertions.assertFalse(Validator.doCheckFieldUrl("https://ast.ptai:8443"));
    }
}