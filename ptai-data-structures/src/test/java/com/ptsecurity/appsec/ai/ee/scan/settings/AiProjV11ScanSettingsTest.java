package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.DotNetSettings.ProjectType;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.MailingProjectSettings;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.PHP;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem.Format.EXACTMATCH;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem.Format.WILDCARD;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.ScanLevel.FULL;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.ScanScope.DOMAIN;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V11;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Read and parse data from scan settings (aiproj) v.1.1 JSON resource file")
class AiProjV11ScanSettingsTest {
    @Test
    @DisplayName("Load OWASP Bricks scan settings")
    public void owaspBricks() {
        String data = getResourceString("json/scan/settings/v11/settings.php-owasp-bricks.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);

        assertEquals(V11, settings.getVersion());
        assertEquals("junit-php-owasp-bricks", settings.getProjectName());
        assertEquals(PHP, settings.getProgrammingLanguage());

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
    }
}