package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

class JsonSettingsVerifierTest {

    @Test
    void verify() {
        try {
            JsonSettingsVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\project_file.aiproj"))));
            JsonSettingsVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.0.json"))));
            JsonSettingsVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.1.json"))));
            JsonSettingsVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.incomplete.json"))));
            JsonSettingsVerifier.verify(new String(Files.readAllBytes(Paths.get("src\\test\\resources\\json\\settings\\settings.incorrect.json"))));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}