package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem;
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
class UnifiedAiProjV11ScanSettingsTest {
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

    @Test
    @DisplayName("Load all possible scan settings")
    public void full() {
        String data = getResourceString("json/scan/settings/v11/settings.full.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);

        assertEquals(V11, settings.getVersion());
        assertEquals("full", settings.getProjectName());
        assertEquals(PHP, settings.getProgrammingLanguage());

        assertTrue(settings.getScanModules().contains(VULNERABLESOURCECODE));
        assertTrue(settings.getScanModules().contains(DATAFLOWANALYSIS));
        assertTrue(settings.getScanModules().contains(PATTERNMATCHING));
        assertTrue(settings.getScanModules().contains(COMPONENTS));
        assertTrue(settings.getScanModules().contains(CONFIGURATION));
        assertTrue(settings.getScanModules().contains(BLACKBOX));

        assertEquals("--log-level=trace", settings.getCustomParameters());

        assertFalse(settings.isUseSastRules());
        assertFalse(settings.isUseCustomPmRules());
        assertTrue(settings.isUseSecurityPolicies());
        assertFalse(settings.isSkipGitIgnoreFiles());
        assertTrue(settings.isUsePublicAnalysisMethod());
        assertTrue(settings.isDownloadDependencies());

        @NonNull BlackBoxSettings blackBoxSettings = settings.getBlackBoxSettings();
        assertEquals("https://missing.ptdemo.local", blackBoxSettings.getSite());
        assertEquals(FULL, blackBoxSettings.getScanLevel());
        assertTrue(blackBoxSettings.getSslCheck());
        assertEquals(DOMAIN, blackBoxSettings.getScanScope());

        @NonNull List<AddressListItem> addresses = blackBoxSettings.getBlackListedAddresses();
        assertEquals(2, addresses.size());
        assertTrue(addresses.stream().anyMatch(a -> (
                a.getAddress().equals("https://test.ptdemo.local/admin/*") && WILDCARD == a.getFormat())));
        assertTrue(addresses.stream().anyMatch(a -> (
                a.getAddress().equals("https://test.ptdemo.local/setup") && EXACTMATCH == a.getFormat())));

        addresses = blackBoxSettings.getWhiteListedAddresses();
        assertEquals(2, addresses.size());
        assertTrue(addresses.stream().anyMatch(a -> (
                a.getAddress().equals("https://test.ptdemo.local/sales") && EXACTMATCH == a.getFormat())));
        assertTrue(addresses.stream().anyMatch(a -> (
                a.getAddress().equals("https://test.ptdemo.local/users/*") && WILDCARD == a.getFormat())));

        List<Pair<String, String>> headers = blackBoxSettings.getHttpHeaders();
        assertEquals(1, headers.size());
        assertTrue(headers.stream().anyMatch(h -> (
                h.getLeft().equals("ptai-scan") && h.getRight().equals("ptai-scan-header-value"))));

        @NonNull BlackBoxSettings.Authentication authentication = blackBoxSettings.getAuthentication();
        assertTrue(authentication instanceof BlackBoxSettings.FormAuthentication);
        BlackBoxSettings.FormAuthentication form = (BlackBoxSettings.FormAuthentication) authentication;
        assertEquals(BlackBoxSettings.FormAuthentication.DetectionType.AUTO, form.getDetectionType());
        assertEquals("admin", form.getLogin());
        assertEquals("P@ssw0rd", form.getPassword());
        assertEquals("https://site.example.com:8888/path", form.getFormAddress());
        assertEquals("Welcome", form.getValidationTemplate());

        @NonNull BlackBoxSettings.ProxySettings proxySettings = settings.getBlackBoxSettings().getProxySettings();
        assertTrue(proxySettings.getEnabled());
        assertEquals(BlackBoxSettings.ProxySettings.Type.HTTP, proxySettings.getType());
        assertEquals("192.168.0.1", proxySettings.getHost());
        assertEquals(3128, proxySettings.getPort());
        assertEquals("admin", proxySettings.getLogin());
        assertEquals("P@ssw0rd", proxySettings.getPassword());

        assertTrue(blackBoxSettings.getRunAutocheckAfterScan());

        @NonNull MailingProjectSettings mailingProjectSettings = settings.getMailingProjectSettings();
        assertTrue(mailingProjectSettings.getEnabled());
        assertEquals("PTDemo", mailingProjectSettings.getMailProfileName());
        assertTrue(mailingProjectSettings.getEmailRecipients().contains("developer@ptdemo.local"));
        assertTrue(mailingProjectSettings.getEmailRecipients().contains("ciso@ptdemo.local"));
    }
}