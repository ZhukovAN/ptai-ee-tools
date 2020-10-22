package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class MessagesTest {
    @Test
    public void testMessages() {
        Locale.setDefault(Locale.ROOT);
        String message = Messages.captions_config_displayName();
        System.out.println(message);
    }
}