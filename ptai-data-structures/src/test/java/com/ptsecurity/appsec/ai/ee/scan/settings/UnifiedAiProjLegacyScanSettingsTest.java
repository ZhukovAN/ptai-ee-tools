package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.core.JsonParseException;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.misc.tools.BaseTest;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Read and parse data from legacy scan settings (aiproj) JSON resource file")
class UnifiedAiProjLegacyScanSettingsTest extends BaseTest {
    @Test
    @DisplayName("Set JSON field values")
    public void setJsonFieldValues() {
        String json = "{ }";
        Configuration config = Configuration.builder().options(Option.SUPPRESS_EXCEPTIONS).build();
        assertNull(JsonPath.using(config).parse(json).read("$.enabled"));
        String changedJson = JsonPath.using(config).parse(json).put("$", "enabled", true).jsonString();
        assertNotEquals(json, changedJson);
        json = JsonPath.using(config).parse(json).put("$", "enabled", false).jsonString();
        assertNotEquals(json, changedJson);
    }

    @Test
    @SneakyThrows
    @DisplayName("Fail settings.incorrect.aiproj file with missing quote in project name")
    public void failIncorrectAiProj() {
        String data = getResourceString("json/scan/settings/legacy/settings.incorrect.aiproj");
        GenericException genericException = Assertions.assertThrows(GenericException.class, () -> UnifiedAiProjScanSettings.loadSettings(data));
        Assertions.assertEquals(genericException.getCause().getClass(), JsonParseException.class);
    }

    @Test
    @SneakyThrows
    @DisplayName("Fail legacy AIPROJ with none or null SolutionFile field")
    public void checkSolutionFile() {
        final String solutionNull = getResourceString("json/scan/settings/legacy/settings.csharp.solution.null.aiproj");
        assertDoesNotThrow(() -> UnifiedAiProjScanSettings.loadSettings(solutionNull).toJson());
        String solutionEmpty = getResourceString("json/scan/settings/legacy/settings.csharp.solution.none.aiproj");
        assertDoesNotThrow(() -> UnifiedAiProjScanSettings.loadSettings(solutionEmpty).toJson());
    }

    @Test
    @SneakyThrows
    @DisplayName("Check legacy AIPROJ with UNIX-path SolutionFile field")
    public void checkUnixSolutionFile() {
        final String scanSettings = getResourceString("json/scan/settings/v11/settings.unix.solutionfile.json");
        UnifiedAiProjScanSettings settings = assertDoesNotThrow(() -> UnifiedAiProjScanSettings.loadSettings(scanSettings));
        assertDoesNotThrow(() -> UnifiedAiProjScanSettings.loadSettings(settings.toJson()).toJson());
    }

    @Test
    @SneakyThrows
    @DisplayName("Fail legacy AIPROJ with case-insensitive enum")
    public void failCaseInsensitiveEnum() {
        final String data = getResourceString("json/scan/settings/legacy/settings.case-insensitive.aiproj");
        assertThrows(GenericException.class, () -> UnifiedAiProjScanSettings.loadSettings(data));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load minimal scan settings that contain project name and language only")
    public void loadMinimalAiProj() {
        String data = getResourceString("json/scan/settings/legacy/settings.minimal.aiproj");
        @NonNull
        UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        assertEquals(UnifiedAiProjScanSettings.Version.LEGACY, settings.getVersion());
        Assertions.assertNotNull(settings);
        assertTrue("Test Project".equalsIgnoreCase(settings.getProjectName()));
        Assertions.assertEquals(ScanResult.ScanSettings.Language.PHP, settings.getProgrammingLanguage());
    }

    @Test
    @SneakyThrows
    @DisplayName("Load generic scan settings that contain project name and language only")
    public void loadGenericAiProj() {
        String data = getResourceString("json/scan/settings/legacy/settings.generic.aiproj");
        @NonNull
        UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        assertEquals(UnifiedAiProjScanSettings.Version.LEGACY, settings.getVersion());
        assertTrue("JSON-based Maven project".equalsIgnoreCase(settings.getProjectName()));
        Assertions.assertEquals(ScanResult.ScanSettings.Language.JAVA, settings.getProgrammingLanguage());
        assertTrue(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.VULNERABLESOURCECODE));
        assertTrue(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.CONFIGURATION));
        assertTrue(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.COMPONENTS));
        assertFalse(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.DATAFLOWANALYSIS));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load DAST-only settings")
    public void loadDastOnlyAiProj() {
        String data = getResourceString("json/scan/settings/legacy/settings.dast.aiproj");
        @NonNull
        UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        assertEquals(UnifiedAiProjScanSettings.Version.LEGACY, settings.getVersion());
        assertTrue("Test project".equalsIgnoreCase(settings.getProjectName()));
        assertTrue(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.BLACKBOX));
        assertEquals(1, settings.getScanModules().size());
        assertFalse(settings.getBlackBoxSettings().runAutocheckAfterScan);
        assertEquals("http://localhost:8080/", settings.getBlackBoxSettings().getSite());
        assertNull(settings.getBlackBoxSettings().getProxySettings());
    }

    @Test
    @SneakyThrows
    @DisplayName("Load JavaScript settings")
    public void loadJavaScriptAiProj() {
        String data = getResourceString("json/scan/settings/legacy/settings.javascript-vnwa.aiproj");
        @NonNull
        UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        assertEquals(UnifiedAiProjScanSettings.Version.LEGACY, settings.getVersion());
        assertTrue("junit-javascript-vnwa".equalsIgnoreCase(settings.getProjectName()));
        assertEquals(ScanBrief.ScanSettings.Language.JAVASCRIPT, settings.getProgrammingLanguage());
        assertTrue(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.VULNERABLESOURCECODE));
        assertTrue(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.DATAFLOWANALYSIS));
        assertTrue(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.PATTERNMATCHING));
        assertTrue(settings.getScanModules().contains(UnifiedAiProjScanSettings.ScanModule.CONFIGURATION));
    }

    @Test
    @DisplayName("Convert enums from strings")
    void convertEnums() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            ScanBrief.ScanSettings.Language.valueOf(ScanBrief.ScanSettings.Engine.BLACKBOX.name());
        });
    }

    @Test
    @DisplayName("Parse all the legacy AIPROJ files")
    @SneakyThrows
    void parseAll() {
        List<String> resources = ResourcesHelper.getResourcesList("json/scan/settings/legacy");
        for (String resourceName : resources) {
            if (resourceName.contains(".incorrect.")) continue;
            String data = getResourceString("json/scan/settings/legacy/" + resourceName);
            System.out.println(resourceName);
            UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
            assertEquals(UnifiedAiProjScanSettings.Version.LEGACY, settings.getVersion());
        }
    }

}