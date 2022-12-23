package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.misc.tools.BaseTest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.jvnet.localizer.Localizable;

import java.text.MessageFormat;
import java.util.Locale;

@Slf4j
@DisplayName("Test i18n resources")
class ResourcesTest extends BaseTest {
    @Test
    @DisplayName("Test i18n localization english resources")
    public void testEnglishMessages() {
        Localizable english = Resources._i18n_misc_enums_locale_english_label();
        Assertions.assertTrue(english.toString(Locale.ENGLISH).equalsIgnoreCase("English"));
    }

    @Test
    @DisplayName("Test i18n localization russian resources")
    public void testRussianMessages() {
        Localizable english = Resources._i18n_misc_enums_locale_english_label();
        Assertions.assertTrue(english.toString(new Locale("ru")).equalsIgnoreCase("Английский"));
    }

    @Test
    @DisplayName("Test MessageFormat")
    public void messageFormat() {
        String result = MessageFormat.format("{0} test #{1} started", "MessageFormat", 1);
        Assertions.assertEquals("MessageFormat test #1 started", result);
    }
}