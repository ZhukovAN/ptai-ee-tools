package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.jvnet.localizer.Localizable;

import java.util.Locale;

class ResourcesTest {
    @DisplayName("Test i18n localization english resources")
    @Test
    public void testEnglishMessages() {
        Localizable english = Resources._captions_locale_english_displayName();
        Assertions.assertTrue(english.toString(Locale.ENGLISH).equalsIgnoreCase("English"));
    }

    @DisplayName("Test i18n localization russian resources")
    @Test
    public void testRussianMessages() {
        Localizable english = Resources._captions_locale_english_displayName();
        Assertions.assertTrue(english.toString(new Locale("ru")).equalsIgnoreCase("Английский"));
    }
}