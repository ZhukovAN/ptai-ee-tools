package com.ptsecurity.appsec.ai.ee.test.scan.settings;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
// import com.ptsecurity.appsec.ai.ee.scan.settings.v411.AiProjScanSettings;
import com.ptsecurity.misc.tools.BaseTest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

@Slf4j
@DisplayName("Read and parse data from scan settings (aiproj) JSON resource file")
public class AiProjScanSettingsTest extends BaseTest {
    /*
    @Test
    @SneakyThrows
    @DisplayName("Fail settings.incorrect.aiproj file with missing quote in project name")
    public void failIncorrectAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/legacy/settings.incorrect.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        Assertions.assertThrows(JsonParseException.class, () -> mapper.readValue(inputStream, AiProjScanSettings.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load minimal scan settings that contain project name and language only")
    public void loadMinimalAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/legacy/settings.minimal.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("Test Project".equalsIgnoreCase(settings.getProjectName()));
        Assertions.assertEquals(ScanResult.ScanSettings.Language.PHP, settings.getProgrammingLanguage());
    }

    @Test
    @SneakyThrows
    @DisplayName("Load generic scan settings that contain project name and language only")
    public void loadGenericAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/legacy/settings.generic.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("JSON-based Maven project".equalsIgnoreCase(settings.getProjectName()));
        Assertions.assertEquals(ScanResult.ScanSettings.Language.JAVA, settings.getProgrammingLanguage());
    }

    @Test
    @SneakyThrows
    @DisplayName("Load DAST-only settings")
    public void loadDastOnlyAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/legacy/settings.dast.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("Test project".equalsIgnoreCase(settings.getProjectName()));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load JavaScript settings")
    public void loadJavaScriptAiProj() {
        InputStream inputStream = getResourceStream("json/scan/settings/legacy/settings.javascript-vnwa.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("junit-javascript-vnwa".equalsIgnoreCase(settings.getProjectName()));
    }

    @Test
    @DisplayName("Convert enums from strings")
    void convertEnums() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            new AiProjScanSettings().setProgrammingLanguage(ScanBrief.ScanSettings.Language.valueOf(ScanBrief.ScanSettings.Engine.BLACKBOX.name()));
        });
    }

     */
}
