package com.ptsecurity.misc.tools.helpers;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class UrlHelperTest {
    @Test
    @DisplayName("Check UrlHelper advanced settings")
    public void checkAdvancedSettings() {
        Assertions.assertTrue(UrlHelper.checkUrl("http://ptai.domain.local"));
        Assertions.assertTrue(UrlHelper.checkUrl("http://ptai.domain.test"));
        Assertions.assertTrue(UrlHelper.checkUrl("https://ptai.domain.local"));
        Assertions.assertTrue(UrlHelper.checkUrl("http://ptai.local"));
        Assertions.assertTrue(UrlHelper.checkUrl("http://localhost"));
        Assertions.assertTrue(UrlHelper.checkUrl("https://192.168.0.1:443"));
        Assertions.assertTrue(UrlHelper.checkUrl("https://localhost:443"));
        Assertions.assertTrue(UrlHelper.checkUrl("http://ptai.github.com:443"));
    }
}