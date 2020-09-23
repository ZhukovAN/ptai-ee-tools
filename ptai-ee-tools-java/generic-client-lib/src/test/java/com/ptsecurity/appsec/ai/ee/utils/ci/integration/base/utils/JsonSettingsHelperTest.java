package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.JsonSettingsHelper;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

class JsonSettingsHelperTest {

    @Test
    void verify() {
        try {
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\project_file.aiproj"))));
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.0.json"))));
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.1.json"))));
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.incomplete.json"))));
            JsonSettingsHelper.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.incorrect.json"))));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}