package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

@DisplayName("Check JSON settings helper")
class JsonSettingsHelperTest {

    @Test
    @DisplayName("Check miscellaneous JSON policy helper")
    void parseJsonSettings() {
        Assertions.assertDoesNotThrow(() -> {
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\project_file.aiproj"))));
        });
        Assertions.assertDoesNotThrow(() -> {
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.aiproj"))));
        });
        Assertions.assertDoesNotThrow(() -> {
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.0.json"))));
        });
        Assertions.assertDoesNotThrow(() -> {
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.1.json"))));
        });
        Assertions.assertThrows(ApiException.class, () -> {
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.incomplete.json"))));
        });
        Assertions.assertThrows(ApiException.class, () -> {
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.incorrect.json"))));
        });
    }
}