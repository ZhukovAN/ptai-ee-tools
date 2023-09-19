package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.ValidationMessage;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.JavaVersion;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.ProgrammingLanguage;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.blackbox.ScanLevel;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.blackbox.ScanScope;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;
import java.util.stream.Collectors;

import static com.networknt.schema.ValidatorTypeCode.ADDITIONAL_PROPERTIES;
import static com.networknt.schema.ValidatorTypeCode.FORMAT;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType.AUTO;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType.MANUAL;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_11;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_8;
import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.DotNetProjectType.*;
import static com.ptsecurity.misc.tools.helpers.CollectionsHelper.isEmpty;
import static java.lang.String.CASE_INSENSITIVE_ORDER;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Slf4j
@SuppressWarnings({"deprecation"})
public class AiProjLegacyScanSettings extends UnifiedAiProjScanSettings {
    public AiProjLegacyScanSettings(@NonNull final JsonNode rootNode) {
        super(rootNode);
    }

    @Override
    public @NonNull String getProjectName() {
        return S("ProjectName");
    }

    @Override
    public ScanBrief.ScanSettings.@NonNull Language getProgrammingLanguage() {
        return PROGRAMMING_LANGUAGE_MAP.get(S("ProgrammingLanguage"));
    }

    @Override
    public UnifiedAiProjScanSettings setProgrammingLanguage(ScanBrief.ScanSettings.@NonNull Language value) {
        for (String language : PROGRAMMING_LANGUAGE_MAP.keySet()) {
            if (!PROGRAMMING_LANGUAGE_MAP.get(language).equals(value)) continue;
            rootNode.put("ProgrammingLanguage", language);
            break;
        }
        return this;
    }

    @Accessors(fluent = true)
    @RequiredArgsConstructor
    private enum ScanAppType {
        PHP("Php"),
        JAVA("Java"),
        CSHARP("CSharp"),
        CONFIGURATION("Configuration"),
        FINGERPRINT("Fingerprint"),
        DEPENDENCYCHECK("DependencyCheck"),
        PMTAINT("PmTaint"),
        BLACKBOX("BlackBox"),
        JAVASCRIPT("JavaScript");

        @Getter
        private final String value;
        private static final Map<String, ScanAppType> VALUES = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));

        static {
            for (ScanAppType f : values()) VALUES.put(f.value, f);
        }

        public static ScanAppType from(@NonNull final String value) {
            return VALUES.get(value);
        }
    }

    /**
     * Set of ScanAppType values that support abstract interpretation
     */
    private static final Set<ScanAppType> SCAN_APP_TYPE_AI = new HashSet<>(Arrays.asList(
            ScanAppType.PHP,
            ScanAppType.JAVA,
            ScanAppType.CSHARP,
            ScanAppType.JAVASCRIPT));

    private static final Map<String, ScanBrief.ScanSettings.Language> PROGRAMMING_LANGUAGE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, UnifiedAiProjScanSettings.DotNetSettings.ProjectType> DOTNET_PROJECT_TYPE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<Integer, BlackBoxSettings.ProxySettings.Type> BLACKBOX_PROXY_TYPE_MAP = new HashMap<>();
    private static final Map<String, BlackBoxSettings.ScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<String, BlackBoxSettings.ScanScope> BLACKBOX_SCAN_SCOPE_MAP = new TreeMap<>(Comparator.nullsFirst(CASE_INSENSITIVE_ORDER));
    private static final Map<Integer, UnifiedAiProjScanSettings.BlackBoxSettings.Authentication.Type> BLACKBOX_AUTH_TYPE_MAP = new HashMap<>();


    static {
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.C_PLUS_PLUS.value(), ScanBrief.ScanSettings.Language.CPP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.GO.value(), ScanBrief.ScanSettings.Language.GO);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.JAVA_SCRIPT.value(), ScanBrief.ScanSettings.Language.JAVASCRIPT);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.C_SHARP.value(), ScanBrief.ScanSettings.Language.CSHARP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.JAVA.value(), ScanBrief.ScanSettings.Language.JAVA);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.KOTLIN.value(), ScanBrief.ScanSettings.Language.KOTLIN);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.SQL.value(), ScanBrief.ScanSettings.Language.SQL);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.PYTHON.value(), ScanBrief.ScanSettings.Language.PYTHON);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.SWIFT.value(), ScanBrief.ScanSettings.Language.SWIFT);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.VB.value(), ScanBrief.ScanSettings.Language.VB);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.PHP.value(), ScanBrief.ScanSettings.Language.PHP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.OBJECTIVE_C.value(), ScanBrief.ScanSettings.Language.OBJECTIVEC);

        DOTNET_PROJECT_TYPE_MAP.put(NONE.value(), DotNetSettings.ProjectType.NONE);
        DOTNET_PROJECT_TYPE_MAP.put(SOLUTION.value(), DotNetSettings.ProjectType.SOLUTION);
        DOTNET_PROJECT_TYPE_MAP.put(WEB_SITE.value(), DotNetSettings.ProjectType.WEBSITE);

        BLACKBOX_PROXY_TYPE_MAP.put(0, BlackBoxSettings.ProxySettings.Type.HTTP);
        BLACKBOX_PROXY_TYPE_MAP.put(1, BlackBoxSettings.ProxySettings.Type.HTTPNOCONNECT);
        BLACKBOX_PROXY_TYPE_MAP.put(2, BlackBoxSettings.ProxySettings.Type.SOCKS4);
        BLACKBOX_PROXY_TYPE_MAP.put(3, BlackBoxSettings.ProxySettings.Type.SOCKS5);

        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NONE.value(), BlackBoxSettings.ScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FAST.value(), BlackBoxSettings.ScanLevel.FAST);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NORMAL.value(), BlackBoxSettings.ScanLevel.NORMAL);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FULL.value(), BlackBoxSettings.ScanLevel.FULL);

        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.PATH.value(), BlackBoxSettings.ScanScope.PATH);
        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.DOMAIN.value(), BlackBoxSettings.ScanScope.DOMAIN);
        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.FOLDER.value(), BlackBoxSettings.ScanScope.FOLDER);

        BLACKBOX_AUTH_TYPE_MAP.put(0, BlackBoxSettings.Authentication.Type.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(1, BlackBoxSettings.Authentication.Type.HTTP);
        BLACKBOX_AUTH_TYPE_MAP.put(2, BlackBoxSettings.Authentication.Type.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(3, BlackBoxSettings.Authentication.Type.COOKIE);
    }

    @Override
    public Set<ScanModule> getScanModules() {
        Set<ScanModule> res = new HashSet<>();
        String scanAppType = S("ScanAppType");
        if (isEmpty(scanAppType)) return res;
        Set<ScanAppType> scanAppTypes = Arrays.stream(scanAppType.split("[, ]+"))
                .map(ScanAppType::from)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        // See internal wiki pageId=193599549
        // "Vulnerable authentication code" checkbox means that we enabled
        // AI-supported PHP / Java / C# / JS scan mode
        boolean abstractInterpretationCoreUsed = scanAppTypes.stream().anyMatch(SCAN_APP_TYPE_AI::contains);
        if (abstractInterpretationCoreUsed) res.add(ScanModule.VULNERABLESOURCECODE);

        if (B("UseTaintAnalysis") && scanAppTypes.contains(ScanAppType.PMTAINT))
            res.add(ScanModule.DATAFLOWANALYSIS);
        if (B("UsePmAnalysis") && scanAppTypes.contains(ScanAppType.PMTAINT))
            res.add(ScanModule.PATTERNMATCHING);
        if (scanAppTypes.contains(ScanAppType.CONFIGURATION)) res.add(ScanModule.CONFIGURATION);
        if (scanAppTypes.contains(ScanAppType.BLACKBOX)) res.add(ScanModule.BLACKBOX);
        if (scanAppTypes.contains(ScanAppType.DEPENDENCYCHECK) || scanAppTypes.contains(ScanAppType.FINGERPRINT))
            res.add(ScanModule.COMPONENTS);
        return res;
    }

    @Override
    public UnifiedAiProjScanSettings setScanModules(@NonNull Set<ScanModule> modules) {
        Set<String> legacyModules = new HashSet<>();
        // Php, Java, CSharp, JavaScript, Configuration, Fingerprint, PmTaint, BlackBox
        if (modules.contains(ScanModule.CONFIGURATION)) legacyModules.add(ScanAppType.CONFIGURATION.value());
        if (modules.contains(ScanModule.COMPONENTS)) legacyModules.add(ScanAppType.FINGERPRINT.value());
        if (modules.contains(ScanModule.BLACKBOX)) legacyModules.add(ScanAppType.BLACKBOX.value());
        if (modules.contains(ScanModule.PATTERNMATCHING) || modules.contains(ScanModule.DATAFLOWANALYSIS))
            legacyModules.add(ScanAppType.PMTAINT.value());
        if (modules.contains(ScanModule.VULNERABLESOURCECODE)) {
            ScanBrief.ScanSettings.Language language = getProgrammingLanguage();
            if (ScanBrief.ScanSettings.Language.PHP == language)
                legacyModules.add(ScanAppType.PHP.value());
            else if (ScanBrief.ScanSettings.Language.JAVA == language)
                legacyModules.add(ScanAppType.JAVA.value());
            else if (ScanBrief.ScanSettings.Language.CSHARP == language)
                legacyModules.add(ScanAppType.CSHARP.value());
            else if (ScanBrief.ScanSettings.Language.JAVASCRIPT == language)
                legacyModules.add(ScanAppType.JAVASCRIPT.value());
        }
        String modulesList = String.join(", ", new HashSet<>(legacyModules));
        rootNode.put("ScanAppType", modulesList);
        return this;
    }

    private BlackBoxSettings.ProxySettings convertProxySettings(@NonNull final JsonNode proxySettings) {
        return BlackBoxSettings.ProxySettings.builder()
                .enabled(B(proxySettings, "IsEnabled"))
                .type(BLACKBOX_PROXY_TYPE_MAP.get(I(proxySettings, "Type")))
                .host(S(proxySettings, "Host"))
                .port(I(proxySettings, "Port"))
                .login(S(proxySettings, "Username"))
                .password(S(proxySettings, "Password"))
                .build();
    }

    private BlackBoxSettings.Authentication convertAuthentication(@NonNull final JsonNode auth) {
        log.trace("Check if AIPROJ authentication field is defined");
        if (N(auth, "credentials").isMissingNode()) {
            log.info("Explicitly set authentication type NONE as there's no authentication settings defined");
            return BlackBoxSettings.Authentication.NONE;
        }
        BlackBoxSettings.Authentication.Type authType;
        authType = BLACKBOX_AUTH_TYPE_MAP.getOrDefault(I(auth, "credentials.type"), BlackBoxSettings.Authentication.Type.NONE);

        if (BlackBoxSettings.Authentication.Type.FORM == authType) {
            return BlackBoxSettings.FormAuthentication.builder()
                    .type(authType)
                    .detectionType(isEmpty(S(auth, "form_xpath")) ? AUTO : MANUAL)
                    .loginKey(S(auth, "credentials.login.name"))
                    .passwordKey(S(auth, "credentials.password.name"))
                    .login(S(auth, "credentials.login.value"))
                    .password(S(auth, "credentials.password.value"))
                    .formAddress(S(auth, "form_url"))
                    .xPath(S(auth, "form_xpath"))
                    .validationTemplate(S(auth, "regexp_of_success"))
                    .build();
        } else if (BlackBoxSettings.Authentication.Type.HTTP == authType) {
            return BlackBoxSettings.HttpAuthentication.builder()
                    .login(S(auth, "credentials.login.value"))
                    .password(S(auth, "credentials.password.value"))
                    .validationAddress(S(auth, "test_url"))
                    .build();
        } else if (BlackBoxSettings.Authentication.Type.COOKIE == authType) {
            return BlackBoxSettings.CookieAuthentication.builder()
                    .cookie(S(auth, "credentials.cookie"))
                    .validationAddress(S(auth, "test_url"))
                    .validationTemplate(S(auth, "regexp_of_success"))
                    .build();
        } else
            return BlackBoxSettings.Authentication.NONE;
    }

    private List<Pair<String, String>> convertHeaders(@NonNull final JsonNode headers) {
        if (!headers.isArray()) return null;
        List<Pair<String, String>> res = new ArrayList<>();
        for (JsonNode header : headers) {
            if (!header.isArray()) {
                log.trace("Skip non-array item");
                continue;
            }
            List<String> headerNameAndValues = new ArrayList<>();
            for (JsonNode item : header) {
                if (!item.isValueNode()) continue;
                headerNameAndValues.add(item.asText());
            }
            if (isEmpty(headerNameAndValues)) {
                log.trace("Skip empty headers");
                continue;
            }
            if (isEmpty(headerNameAndValues.get(0))) {
                log.trace("Skip header with empty name");
                continue;
            }
            for (int i = 1; i < headerNameAndValues.size(); i++)
                res.add(
                        new ImmutablePair<>(headerNameAndValues.get(0), headerNameAndValues.get(i)));

        }
        return isEmpty(res) ? null : res;
    }

    @Override
    public BlackBoxSettings getBlackBoxSettings() {
        if (!getScanModules().contains(ScanModule.BLACKBOX)) return null;

        BlackBoxSettings blackBoxSettings = new BlackBoxSettings();

        blackBoxSettings.setScanLevel(BLACKBOX_SCAN_LEVEL_MAP.getOrDefault(S("Level"), BlackBoxSettings.ScanLevel.NONE));
        blackBoxSettings.setRunAutocheckAfterScan(B("RunAutocheckAfterScan"));

        blackBoxSettings.setSite(S("Site"));
        blackBoxSettings.setScanScope(BLACKBOX_SCAN_SCOPE_MAP.getOrDefault(S("ScanScope"), BlackBoxSettings.ScanScope.PATH));
        blackBoxSettings.setSslCheck(false);

        JsonNode proxySettings = N("ProxySettings");
        if (!proxySettings.isMissingNode())
            blackBoxSettings.setProxySettings(convertProxySettings(proxySettings));
        JsonNode customHeaders = N("CustomHeaders");
        if (customHeaders.isArray())
            blackBoxSettings.setHttpHeaders(convertHeaders(customHeaders));
        JsonNode authentication = N("Authentication.auth_item");
        if (!authentication.isMissingNode())
            blackBoxSettings.setAuthentication(convertAuthentication(authentication));

        if (!blackBoxSettings.getRunAutocheckAfterScan()) return blackBoxSettings;

        blackBoxSettings.setAutocheckSite(S("AutocheckSite"));
        proxySettings = N("AutocheckProxySettings");
        if (!proxySettings.isMissingNode())
            blackBoxSettings.setAutocheckProxySettings(convertProxySettings(proxySettings));
        customHeaders = N("AutocheckCustomHeaders");
        if (customHeaders.isArray())
            blackBoxSettings.setAutocheckHttpHeaders(convertHeaders(customHeaders));
        authentication = N("AutocheckAuthentication.auth_item");
        if (!authentication.isMissingNode())
            blackBoxSettings.setAutocheckAuthentication(convertAuthentication(authentication));
        return blackBoxSettings;
    }

    @Override
    public @NonNull Boolean isDownloadDependencies() {
        return B("IsDownloadDependencies");
    }

    @Override
    public UnifiedAiProjScanSettings setDownloadDependencies(@NonNull Boolean value) {
        rootNode.put("IsDownloadDependencies", value);
        return this;
    }

    @Override
    public @NonNull Boolean isUsePublicAnalysisMethod() {
        return B("IsUsePublicAnalysisMethod");
    }

    @Override
    public UnifiedAiProjScanSettings setUsePublicAnalysisMethod(@NonNull Boolean value) {
        rootNode.put("IsUsePublicAnalysisMethod", value);
        return this;
    }

    @Override
    public String getCustomParameters() {
        return S("CustomParameters");
    }

    @Override
    public UnifiedAiProjScanSettings setCustomParameters(String parameters) {
        rootNode.put("CustomParameters", parameters);
        return this;
    }

    @Override
    public DotNetSettings getDotNetSettings() {
        return DotNetSettings.builder()
                .solutionFile(fixSolutionFile(S("SolutionFile")))
                .webSiteFolder(S("WebSiteFolder"))
                .projectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(S("ProjectType"), DotNetSettings.ProjectType.NONE))
                .build();
    }

    @Override
    public JavaSettings getJavaSettings() {
        return JavaSettings.builder()
                .unpackUserPackages(B("IsUnpackUserPackages"))
                .userPackagePrefixes(S("UserPackagePrefixes"))
                .javaVersion(JavaVersion._0.value().equals(I("JavaVersion")) ? v1_8 : v1_11)
                .parameters(S("JavaParameters"))
                .build();
    }

    @Override
    public @NonNull Boolean isSkipGitIgnoreFiles() {
        log.trace("No skip .gitignore files support for legacy AIPROJ schema");
        return false;
    }

    @Override
    public @NonNull Boolean isUseSastRules() {
        return B("UseSastRules");
    }

    @Override
    public @NonNull Boolean isUseCustomPmRules() {
        log.trace("No custom PM rules support for legacy AIPROJ schema");
        return false;
    }

    @Override
    public @NonNull Boolean isUseCustomYaraRules() {
        return B("UseCustomYaraRules");
    }

    @Override
    public @NonNull Boolean isUseSecurityPolicies() {
        return B("UseSecurityPolicies");
    }

    @Override
    public MailingProjectSettings getMailingProjectSettings() {
        log.trace("No mail settings support for legacy AIPROJ schema");
        return null;
    }

    @Override
    public @NonNull String getJsonSchema() {
        return ResourcesHelper.getResourceString("aiproj/schema/aiproj-legacy.json");
    }

    @Override
    public Set<ParseResult.Message> processErrorMessages(Set<ValidationMessage> errors) {
        Set<ParseResult.Message> result = new HashSet<>();
        for (ValidationMessage error : errors) {
            ParseResult.Message.Type type = error.getCode().equals(ADDITIONAL_PROPERTIES.getErrorCode())
                    ? ParseResult.Message.Type.WARNING
                    : ParseResult.Message.Type.ERROR;
            result.add(ParseResult.Message.builder()
                    .type(type)
                    .text(error.getMessage())
                    .build());
        }
        return result;
    }

    @Override
    public Version getVersion() {
        return Version.LEGACY;
    }
}
