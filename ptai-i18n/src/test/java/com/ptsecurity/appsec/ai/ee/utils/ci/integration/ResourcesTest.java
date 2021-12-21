package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.jvnet.localizer.Localizable;

import java.text.MessageFormat;
import java.util.Locale;

class ResourcesTest {
    @DisplayName("Test i18n localization english resources")
    @Test
    public void testEnglishMessages() {
        Localizable english = Resources._i18n_misc_enums_locale_english_label();
        Assertions.assertTrue(english.toString(Locale.ENGLISH).equalsIgnoreCase("English"));
    }

    @DisplayName("Test i18n localization russian resources")
    @Test
    public void testRussianMessages() {
        Localizable english = Resources._i18n_misc_enums_locale_english_label();
        Assertions.assertTrue(english.toString(new Locale("ru")).equalsIgnoreCase("Английский"));
    }

    @DisplayName("Test MessageFormat")
    @Test
    public void messageFormat() {
        String result = MessageFormat.format("{0} test #{1} started", "MessageFormat", 1);
        Assertions.assertTrue(result.equals("MessageFormat test #1 started"));

    }
}