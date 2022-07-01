package com.ptsecurity.appsec.ai.ee.test.scan.settings;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.settings.v36.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

@DisplayName("Read and parse data from scan settings (aiproj) JSON resource file")
public class AiProjScanSettingsTest extends BaseTest {
    @Test
    @SneakyThrows
    @DisplayName("Fail settings.incorrect.aiproj file with missing quote in project name")
    public void failIncorrectAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/settings.incorrect.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        Assertions.assertThrows(JsonParseException.class, () -> mapper.readValue(inputStream, AiProjScanSettings.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load minimal scan settings that contain project name and language only")
    public void loadMinimalAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/settings.minimal.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("Test Project".equalsIgnoreCase(settings.getProjectName()));
        Assertions.assertEquals(ScanResult.ScanSettings.Language.PHP, settings.getProgrammingLanguage());
    }

    @Test
    @SneakyThrows
    @DisplayName("Load generic scan settings that contain project name and language only")
    public void loadGenericAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/settings.generic.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("JSON-based Maven project".equalsIgnoreCase(settings.getProjectName()));
        Assertions.assertEquals(ScanResult.ScanSettings.Language.JAVA, settings.getProgrammingLanguage());
    }

    @Test
    @SneakyThrows
    @DisplayName("Load DAST-only settings")
    public void loadDastOnlyAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/settings.dast.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("Test project".equalsIgnoreCase(settings.getProjectName()));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load JavaScript settings")
    public void loadJavaScriptAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/settings.javascript-vnwa.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("junit-it-javascript-smoke".equalsIgnoreCase(settings.getProjectName()));
    }

}
