package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.networknt.schema.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.JAVA;
import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.PHP;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem.Format.EXACTMATCH;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem.Format.WILDCARD;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType.MANUAL;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.ScanLevel.FULL;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.ScanScope.DOMAIN;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.BLACKBOX;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.LEGACY;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.Version.V11;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnifiedAiProjScanSettingsTest {
    @Test
    @DisplayName("Serialize unified AIPROJ settings")
    public void serializeToJson() {
        String data = getResourceString("json/scan/settings/v11/settings.full.json");
        @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(data);
        String json = settings.toJson();
        @NonNull UnifiedAiProjScanSettings clonedSettings = UnifiedAiProjScanSettings.loadSettings(json);
        assertEquals(settings.getProgrammingLanguage(), clonedSettings.getProgrammingLanguage());
        clonedSettings.setProgrammingLanguage(ScanBrief.ScanSettings.Language.KOTLIN);
        Assertions.assertNotEquals(settings.getProgrammingLanguage(), clonedSettings.getProgrammingLanguage());
    }

    @SneakyThrows
    @Test
    @DisplayName("Validate JSON schema")
    public void validateJsonSchema() {
        String schema = "{\n" +
                "    \"$schema\": \"http://json-schema.org/draft-04/schema#\",\n" +
                "    \"properties\": {\n" +
                "        \"$schema\": {\n" +
                "            \"type\": \"string\"\n" +
                "        },\n" +
                "        \"Version\": {\n" +
                "            \"type\": \"string\"\n" +
                "        }\n" +
                "    },\n" +
                "\t\"additionalProperties\": false,\n" +
                "    \"required\": [\"Version\"],\n" +
                "    \"title\": \"test\",\n" +
                "    \"type\": \"object\"\n" +
                "}\n";
        JsonSchemaFactory factory = JsonSchemaFactory
                .builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4))
                .addMetaSchema(JsonMetaSchema
                        .builder(JsonMetaSchema.getV4().getUri(), JsonMetaSchema.getV4())
                        .build()).build();
        JsonSchema jsonSchema = factory.getSchema(schema);
        Set<ValidationMessage> errors = jsonSchema.validate(createObjectMapper().readTree("{ \"Version\": \"First\" }"));
        Assertions.assertTrue(errors.isEmpty());
        errors = jsonSchema.validate(createObjectMapper().readTree("{ \"Version\": \"First\", \"Unknown\": \"Some data\" }"));
        Assertions.assertFalse(errors.isEmpty());
    }

    @Test
    @DisplayName("Check legacy and v.1.1 full scan settings parse as unified settings")
    public void checkScanSettings() {
        for (String version : Arrays.asList("legacy", "v11")) {
            String jsonSettings = getResourceString("json/scan/settings/" + version + "/settings.full.json");
            @NonNull UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(jsonSettings);
            assertEquals("v11".equals(version) ? V11 : LEGACY, settings.getVersion());
            checkScanSettings(settings);
        }
    }

    protected void checkScanSettings(UnifiedAiProjScanSettings settings) {
        assertEquals("WebGoat.NET", settings.getProjectName());
        assertEquals(JAVA, settings.getProgrammingLanguage());

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

        assertNotNull(settings.getDotNetSettings());
        assertEquals(UnifiedAiProjScanSettings.DotNetSettings.ProjectType.SOLUTION, settings.getDotNetSettings().getProjectType());
        assertEquals("./WebGoat.NET.sln", settings.getDotNetSettings().getSolutionFile());

        assertNotNull(settings.getJavaSettings());
        assertEquals("-Dfile.encoding=UTF-8", settings.getJavaSettings().getParameters());
        assertTrue(settings.getJavaSettings().getUnpackUserPackages());
        assertEquals("com.ptsecurity.appsec", settings.getJavaSettings().getUserPackagePrefixes());
        assertEquals(UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_11, settings.getJavaSettings().getJavaVersion());

        @NonNull UnifiedAiProjScanSettings.BlackBoxSettings blackBoxSettings = settings.getBlackBoxSettings();
        assertEquals("https://test.ptdemo.local", blackBoxSettings.getSite());
        assertEquals(FULL, blackBoxSettings.getScanLevel());
        assertEquals(DOMAIN, blackBoxSettings.getScanScope());

        if (LEGACY == settings.getVersion())
            assertFalse(blackBoxSettings.getSslCheck());
        else
            assertTrue(blackBoxSettings.getSslCheck());

        if (LEGACY != settings.getVersion()) {
            List<UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem> addresses = blackBoxSettings.getBlackListedAddresses();
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
        }


        List<Pair<String, String>> headers = blackBoxSettings.getHttpHeaders();
        assertEquals(2, headers.size());
        assertTrue(headers.stream().anyMatch(h -> (
                h.getLeft().equals("ptai-scan") && h.getRight().equals("ptai-scan-header-value"))));
        assertTrue(headers.stream().anyMatch(h -> (
                h.getLeft().equals("custom-header") && h.getRight().equals("custom-value"))));

        @NonNull UnifiedAiProjScanSettings.BlackBoxSettings.Authentication authentication = blackBoxSettings.getAuthentication();
        assertTrue(authentication instanceof UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication);
        UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication form = (UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication) authentication;
        assertEquals(MANUAL, form.getDetectionType());
        assertEquals("admin", form.getLogin());
        assertEquals("username", form.getLoginKey());
        assertEquals("P@ssw0rd", form.getPassword());
        assertEquals("password", form.getPasswordKey());
        assertEquals("https://test.ptdemo.local/login", form.getFormAddress());
        assertEquals("/html/body/form", form.getXPath());
        assertEquals("Welcome", form.getValidationTemplate());

        @NonNull UnifiedAiProjScanSettings.BlackBoxSettings.ProxySettings proxySettings = settings.getBlackBoxSettings().getProxySettings();
        assertTrue(proxySettings.getEnabled());
        assertEquals(UnifiedAiProjScanSettings.BlackBoxSettings.ProxySettings.Type.HTTP, proxySettings.getType());
        assertEquals("proxy.ptdemo.local", proxySettings.getHost());
        assertEquals(3128, proxySettings.getPort());
        assertEquals("admin", proxySettings.getLogin());
        assertEquals("P@ssw0rd", proxySettings.getPassword());

        assertTrue(blackBoxSettings.getRunAutocheckAfterScan());

        if (LEGACY != settings.getVersion()) {
            UnifiedAiProjScanSettings.MailingProjectSettings mailingProjectSettings = settings.getMailingProjectSettings();
            assertTrue(mailingProjectSettings.getEnabled());
            assertEquals("PTDemo", mailingProjectSettings.getMailProfileName());
            assertTrue(mailingProjectSettings.getEmailRecipients().contains("developer@ptdemo.local"));
            assertTrue(mailingProjectSettings.getEmailRecipients().contains("ciso@ptdemo.local"));
        }
    }

}