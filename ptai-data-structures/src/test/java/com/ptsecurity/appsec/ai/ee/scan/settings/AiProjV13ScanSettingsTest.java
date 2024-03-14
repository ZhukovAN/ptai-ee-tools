package com.ptsecurity.appsec.ai.ee.scan.settings;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_17;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V13;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.3 JSON resource file")
class AiProjV13ScanSettingsTest {
    @Test
    @DisplayName("Load SmokeJdk scan settings")
    public void SmokeJdk() {
        String data = getResourceString("json/scan/settings/v13/settings.smoke-jdk.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.JavaSettings javaSettings = settings.getJavaSettings();

        assertEquals(V13, settings.getVersion());
        assertEquals("SmokeJdk", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(JAVA));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(PATTERNMATCHING));
        assertTrue(settings.getScanModules().contains(COMPONENTS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertFalse(settings.isUseSastRules());
        assertFalse(settings.isUseCustomPmRules());
        assertFalse(settings.isUseSecurityPolicies());
        assertFalse(settings.isSkipGitIgnoreFiles());

        assertNotNull(javaSettings);
        assertNull(javaSettings.customParameters);
        assertEquals(v1_17, javaSettings.javaVersion);
        assertFalse(javaSettings.usePublicAnalysisMethod);
        assertFalse(javaSettings.downloadDependencies);

        assertNotNull(settings.getMailingProjectSettings());
        assertFalse(settings.getMailingProjectSettings().enabled);
        assertTrue(settings.getMailingProjectSettings().getEmailRecipients().isEmpty());
    }

    @Test
    @DisplayName("Load CSharpWinOnly scan settings")
    public void CSharpWinOnly() {
        String data = getResourceString("json/scan/settings/v13/settings.win-csharp.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.WindowsDotNetSettings windowsDotNetSettings = settings.getWindowsDotNetSettings();

        assertEquals(V13, settings.getVersion());
        assertEquals("CSharpWin", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(CSHARPWINONLY));
        assertTrue(settings.getProgrammingLanguages().contains(KOTLIN));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertTrue(settings.isUseSastRules());
        assertTrue(settings.isUseSecurityPolicies());
        assertTrue(settings.isSkipGitIgnoreFiles());

        assertNotNull(windowsDotNetSettings);
        assertNull(windowsDotNetSettings.customParameters);
        assertTrue(windowsDotNetSettings.usePublicAnalysisMethod);
        assertFalse(windowsDotNetSettings.downloadDependencies);
    }

    @Test
    @DisplayName("Load CSharpJsa scan settings")
    public void CSharpJsa() {
        String data = getResourceString("json/scan/settings/v13/settings.jsa-csharp.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        UnifiedAiProjScanSettings.DotNetSettings windowsDotNetSettings = settings.getDotNetSettings();

        assertEquals(V13, settings.getVersion());
        assertEquals("CSharpJsa", settings.getProjectName());
        assertTrue(settings.getProgrammingLanguages().contains(CSHARP));
        assertTrue(settings.getProgrammingLanguages().contains(RUBY));

        assertTrue(settings.getScanModules().contains(STATICCODEANALYSIS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertTrue(settings.isUseSastRules());
        assertTrue(settings.isUseSecurityPolicies());
        assertTrue(settings.isSkipGitIgnoreFiles());

        assertNotNull(windowsDotNetSettings);
        assertNull(windowsDotNetSettings.customParameters);
        assertTrue(windowsDotNetSettings.usePublicAnalysisMethod);
        assertFalse(windowsDotNetSettings.downloadDependencies);
    }
}
