package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.helpers.aiproj.AiProjHelper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.misc.tools.BaseTest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

class UnifiedAiProjScanSettingsTest extends BaseTest {
    @Test
    @SneakyThrows
    @DisplayName("Fail settings.incorrect.aiproj file with missing quote in project name")
    public void failIncorrectAiProj() {
        String data = getResourceString("json/scan/settings/legacy/settings.incorrect.aiproj");
        UnifiedAiProjScanSettings settings = AiProjHelper.load(data);
        // Assertions.assertThrows(JsonParseException.class, () -> mapper.readValue(inputStream, AiProjScanSettings.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load minimal scan settings that contain project name and language only")
    public void loadMinimalAiProj() {
        String data = getResourceString("json/scan/settings/legacy/settings.minimal.aiproj");
        UnifiedAiProjScanSettings settings = AiProjHelper.load(data);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("Test Project".equalsIgnoreCase(settings.getProjectName()));
        Assertions.assertEquals(ScanResult.ScanSettings.Language.PHP, settings.getProgrammingLanguage());
    }

    @Test
    @SneakyThrows
    @DisplayName("Load generic scan settings that contain project name and language only")
    public void loadGenericAiProj() {
        String data = getResourceString("json/scan/settings/legacy/settings.generic.aiproj");
        UnifiedAiProjScanSettings settings = AiProjHelper.load(data);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("JSON-based Maven project".equalsIgnoreCase(settings.getProjectName()));
        Assertions.assertEquals(ScanResult.ScanSettings.Language.JAVA, settings.getProgrammingLanguage());
    }


}