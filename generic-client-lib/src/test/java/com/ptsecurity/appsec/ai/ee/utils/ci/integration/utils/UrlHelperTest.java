package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import org.apache.commons.validator.routines.DomainValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob.DEFAULT_PTAI_URL;
import static org.junit.jupiter.api.Assertions.*;

class UrlHelperTest {
    @Test
    @DisplayName("Check UrlHelper advanced settings")
    public void checkAdvancedSettings() {
        Assertions.assertTrue(UrlHelper.checkUrl(DEFAULT_PTAI_URL));
        Assertions.assertTrue(UrlHelper.checkUrl("http://ptai.domain.local"));
        Assertions.assertFalse(UrlHelper.checkUrl("http://ptai.domain.test"));
        Assertions.assertTrue(UrlHelper.checkUrl("https://ptai.domain.local"));
        Assertions.assertTrue(UrlHelper.checkUrl("http://ptai.local"));
        Assertions.assertTrue(UrlHelper.checkUrl("http://localhost"));
        Assertions.assertTrue(UrlHelper.checkUrl("https://192.168.0.1:443"));
        Assertions.assertTrue(UrlHelper.checkUrl("https://localhost:443"));
        Assertions.assertTrue(UrlHelper.checkUrl("http://ptai.github.com:443"));
    }
}