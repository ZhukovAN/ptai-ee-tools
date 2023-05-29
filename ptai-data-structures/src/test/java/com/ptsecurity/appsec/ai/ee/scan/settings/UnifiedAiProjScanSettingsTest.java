package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import lombok.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

class UnifiedAiProjScanSettingsTest {
    @Test
    @DisplayName("Serialize unified AIPROJ settings")
    public void serializeToJson() {
        String data = getResourceString("json/scan/settings/v11/settings.full.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        String json = settings.toJson();
        @NonNull UnifiedAiProjScanSettings clonedSettings = UnifiedAiProjScanSettings.loadSettings(json);
        Assertions.assertEquals(settings.getProgrammingLanguage(), clonedSettings.getProgrammingLanguage());
        clonedSettings.setProgrammingLanguage(ScanBrief.ScanSettings.Language.KOTLIN);
        Assertions.assertNotEquals(settings.getProgrammingLanguage(), clonedSettings.getProgrammingLanguage());
    }

}