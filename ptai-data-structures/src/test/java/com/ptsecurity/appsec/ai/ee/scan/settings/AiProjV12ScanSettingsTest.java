package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.JAVA;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V12;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.2 JSON resource file")
class AiProjV12ScanSettingsTest {
    @Test
    @DisplayName("Load SmokeJdk scan settings")
    public void SmokeJdk() {
        String data = getResourceString("json/scan/settings/v12/settings.smoke-jdk.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);

        assertEquals(V12, settings.getVersion());
        assertEquals("SmokeJdk", settings.getProjectName());
        assertEquals(JAVA, settings.getProgrammingLanguage());

        assertTrue(settings.getScanModules().contains(VULNERABLESOURCECODE));
        assertTrue(settings.getScanModules().contains(DATAFLOWANALYSIS));
        assertTrue(settings.getScanModules().contains(PATTERNMATCHING));
        assertTrue(settings.getScanModules().contains(COMPONENTS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));

        assertTrue(StringUtils.isEmpty(settings.getCustomParameters()));

        assertFalse(settings.isUseSastRules());
        assertFalse(settings.isUseCustomPmRules());
        assertFalse(settings.isUseSecurityPolicies());
        assertFalse(settings.isSkipGitIgnoreFiles());
        assertFalse(settings.isUsePublicAnalysisMethod());
        assertFalse(settings.isDownloadDependencies());

        assertNotNull(settings.getMailingProjectSettings());
        assertFalse(settings.getMailingProjectSettings().enabled);
        assertTrue(settings.getMailingProjectSettings().getEmailRecipients().isEmpty());

        assertEquals(settings.getJavaSettings().javaVersion, JavaVersion.v1_17);
    }
}
