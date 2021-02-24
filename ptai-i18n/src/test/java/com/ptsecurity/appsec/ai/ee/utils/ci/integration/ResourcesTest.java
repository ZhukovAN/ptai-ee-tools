package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import org.junit.jupiter.api.Test;

import java.util.Locale;

class ResourcesTest {
    @Test
    public void testMessages() {
        Locale.setDefault(Locale.ROOT);
        String message = Resources.captions_config_displayName();
        System.out.println(message);
    }
}