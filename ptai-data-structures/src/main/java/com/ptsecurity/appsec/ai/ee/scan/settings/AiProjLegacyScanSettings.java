package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.jayway.jsonpath.JsonPath;
import com.networknt.schema.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.JavaVersion;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.ProgrammingLanguage;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.blackbox.ScanLevel;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType.AUTO;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType.MANUAL;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_11;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_8;
import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.DotNetProjectType.*;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Slf4j
@SuppressWarnings({"deprecation"})
public class AiProjLegacyScanSettings extends UnifiedAiProjScanSettings {
    @Override
    public @NonNull String getProjectName() {
        return S("$.ProjectName");
    }

    @Override
    public ScanBrief.ScanSettings.@NonNull Language getProgrammingLanguage() {
        return PROGRAMMING_LANGUAGE_MAP.get(S("$.ProgrammingLanguage"));
    }

    @Override
    public UnifiedAiProjScanSettings setProgrammingLanguage(ScanBrief.ScanSettings.@NonNull Language value) {
        for (String language : PROGRAMMING_LANGUAGE_MAP.keySet()) {
            if (!PROGRAMMING_LANGUAGE_MAP.get(language).equals(value)) continue;
            aiprojDocument.set("$.ProgrammingLanguage", language);
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
        private static final Map<String, ScanAppType> VALUES = new HashMap<>();

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
    /**
     * Set of programming languages values that support abstract interpretation
     */
    private static final Set<ScanBrief.ScanSettings.Language> LANGUAGE_AI = new HashSet<>(Arrays.asList(
            ScanBrief.ScanSettings.Language.PHP,
            ScanBrief.ScanSettings.Language.JAVA,
            ScanBrief.ScanSettings.Language.CSHARP,
            ScanBrief.ScanSettings.Language.VB,
            ScanBrief.ScanSettings.Language.JAVASCRIPT));

    private static final Map<String, ScanBrief.ScanSettings.Language> PROGRAMMING_LANGUAGE_MAP = new HashMap<>();
    private static final Map<String, UnifiedAiProjScanSettings.DotNetSettings.ProjectType> DOTNET_PROJECT_TYPE_MAP = new HashMap<>();
    private static final Map<Integer, BlackBoxSettings.ProxySettings.Type> BLACKBOX_PROXY_TYPE_MAP = new HashMap<>();
    private static final Map<String, BlackBoxSettings.ScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new HashMap<>();
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

        BLACKBOX_AUTH_TYPE_MAP.put(0, BlackBoxSettings.Authentication.Type.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(1, BlackBoxSettings.Authentication.Type.HTTP);
        BLACKBOX_AUTH_TYPE_MAP.put(2, BlackBoxSettings.Authentication.Type.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(3, BlackBoxSettings.Authentication.Type.COOKIE);
    }

    @Override
    public Set<ScanModule> getScanModules() {
        Set<ScanModule> res = new HashSet<>();
        String scanAppType = S("$.ScanAppType");
        if (isEmpty(scanAppType)) return res;
        Set<ScanAppType> scanAppTypes = Arrays.stream(scanAppType.split("[, ]+"))
                .map(ScanAppType::from)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        // See internal wiki pageId=193599549
        // "Vulnerable authentication code" checkbox means that we either enabled AI-supported PHP / Java / C# / JS scan mode ...
        boolean abstractInterpretationCoreUsed = scanAppTypes.stream().anyMatch(SCAN_APP_TYPE_AI::contains);
        // ... or all other languages with PmTaint / UseTaintAnalysis enabled
        boolean taintOnlyLanguageUsed = !LANGUAGE_AI.contains(getProgrammingLanguage())
                && scanAppTypes.contains(ScanAppType.PMTAINT)
                && B("$.UseTaintAnalysis");
        if (abstractInterpretationCoreUsed || taintOnlyLanguageUsed) res.add(ScanModule.VULNERABLESOURCECODE);
        if (B("$.UseTaintAnalysis") && scanAppTypes.contains(ScanAppType.PMTAINT))
            res.add(ScanModule.DATAFLOWANALYSIS);
        if (B("$.UsePmAnalysis") && scanAppTypes.contains(ScanAppType.PMTAINT))
            res.add(ScanModule.PATTERNMATCHING);
        if (scanAppTypes.contains(ScanAppType.CONFIGURATION)) res.add(ScanModule.CONFIGURATION);
        if (scanAppTypes.contains(ScanAppType.BLACKBOX)) res.add(ScanModule.BLACKBOX);
        if (scanAppTypes.contains(ScanAppType.DEPENDENCYCHECK) || scanAppTypes.contains(ScanAppType.FINGERPRINT))
            res.add(ScanModule.COMPONENTS);
        return res;
    }

    @Override
    public UnifiedAiProjScanSettings setScanModules(@NonNull Set<ScanModule> modules) {
        String modulesList = String.join(", ", modules.stream().map(ScanModule::getValue).collect(Collectors.toSet()));
        aiprojDocument.set("$.ScanModules", modulesList);
        return this;
    }

    private BlackBoxSettings.ProxySettings convertProxySettings(@NonNull final Object proxySettings) {
        return BlackBoxSettings.ProxySettings.builder()
                .enabled(B(proxySettings, "$.IsEnabled"))
                .type(BLACKBOX_PROXY_TYPE_MAP.get(I(proxySettings, "$.Type")))
                .host(S(proxySettings, "$.Host"))
                .port(I(proxySettings, "$.Port"))
                .login(S(proxySettings, "$.Username"))
                .password(S(proxySettings, "$.Password"))
                .build();
    }

    private BlackBoxSettings.Authentication convertAuthentication(final Object auth) {
        log.trace("Check if AIPROJ authentication field is defined");
        if (null == auth || null == O(auth, "$.credentials")) {
            log.info("Explicitly set authentication type NONE as there's no authentication settings defined");
            return BlackBoxSettings.Authentication.NONE;
        }
        BlackBoxSettings.Authentication.Type authType;
        authType = BLACKBOX_AUTH_TYPE_MAP.getOrDefault(I(auth, "$.credentials.type"), BlackBoxSettings.Authentication.Type.NONE);

        if (BlackBoxSettings.Authentication.Type.FORM == authType) {
            return BlackBoxSettings.FormAuthentication.builder()
                    .type(authType)
                    .detectionType(isEmpty(S(auth, "$.form_xpath")) ? AUTO : MANUAL)
                    .loginKey(S(auth, "$.credentials.login.name"))
                    .passwordKey(S(auth, "$.credentials.password.name"))
                    .login(S(auth, "$.credentials.login.value"))
                    .password(S(auth, "$.credentials.password.value"))
                    .formAddress(S(auth, "$.form_url"))
                    .xPath(S(auth, "$.form_xpath"))
                    .validationTemplate(S(auth, "$.regexp_of_success"))
                    .build();
        } else if (BlackBoxSettings.Authentication.Type.HTTP == authType) {
            return BlackBoxSettings.HttpAuthentication.builder()
                    .login(S(auth, "$.credentials.login.value"))
                    .password(S(auth, "$.credentials.password.value"))
                    .validationAddress(S(auth, "$.test_url"))
                    .build();
        } else if (BlackBoxSettings.Authentication.Type.COOKIE == authType) {
            return BlackBoxSettings.CookieAuthentication.builder()
                    .cookie(S(auth, "$.credentials.cookie"))
                    .validationAddress(S(auth, "$.test_url"))
                    .validationTemplate(S(auth, "$.regexp_of_success"))
                    .build();
        } else
            return BlackBoxSettings.Authentication.NONE;
    }

    private List<Pair<String, String>> convertHeaders(@NonNull final List<String>[] headers) {
        List<Pair<String, String>> res = new ArrayList<>();
        for (List<String> headerNameAndValues : headers) {
            if (CollectionUtils.isEmpty(headerNameAndValues)) {
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
        return CollectionUtils.isEmpty(res) ? null : res;
    }

    @Override
    public BlackBoxSettings getBlackBoxSettings() {
        if (!getScanModules().contains(ScanModule.BLACKBOX)) return null;

        BlackBoxSettings blackBoxSettings = new BlackBoxSettings();

        blackBoxSettings.setScanLevel(BLACKBOX_SCAN_LEVEL_MAP.getOrDefault(S("$.Level"), BlackBoxSettings.ScanLevel.NONE));
        blackBoxSettings.setRunAutocheckAfterScan(B("$.RunAutocheckAfterScan"));

        blackBoxSettings.setSite(S("$.Site"));
        Object proxySettings = O("$.ProxySettings");
        if (null != proxySettings)
            blackBoxSettings.setProxySettings(convertProxySettings(proxySettings));
        List<String>[] customHeaders = O(aiprojDocument,"$.CustomHeaders");
        if (null != customHeaders)
            blackBoxSettings.setHttpHeaders(convertHeaders(customHeaders));
        Object authentication = O("$.Authentication.auth_item");
        if (null != authentication)
            blackBoxSettings.setAuthentication(convertAuthentication(authentication));

        if (!blackBoxSettings.getRunAutocheckAfterScan()) return blackBoxSettings;

        blackBoxSettings.setAutocheckSite(S("$.AutocheckSite"));
        proxySettings = O("$.AutocheckProxySettings");
        if (null != proxySettings)
            blackBoxSettings.setAutocheckProxySettings(convertProxySettings(proxySettings));
        customHeaders = O(aiprojDocument,"$.AutocheckCustomHeaders");
        if (null != customHeaders)
            blackBoxSettings.setAutocheckHttpHeaders(convertHeaders(customHeaders));
        authentication = O("$.AutocheckAuthentication.auth_item");
        if (null != authentication)
            blackBoxSettings.setAutocheckAuthentication(convertAuthentication(authentication));
        return blackBoxSettings;
    }

    @Override
    public @NonNull Boolean isDownloadDependencies() {
        return B("$.IsDownloadDependencies");
    }

    @Override
    public UnifiedAiProjScanSettings setDownloadDependencies(@NonNull Boolean value) {
        aiprojDocument.set("$.IsDownloadDependencies", value);
        return this;
    }

    @Override
    public @NonNull Boolean isUsePublicAnalysisMethod() {
        return B("$.IsUsePublicAnalysisMethod");
    }

    @Override
    public UnifiedAiProjScanSettings setUsePublicAnalysisMethod(@NonNull Boolean value) {
        aiprojDocument.set("$.IsUsePublicAnalysisMethod", value);
        return this;
    }

    @Override
    public String getCustomParameters() {
        return S("$.CustomParameters");
    }

    @Override
    public UnifiedAiProjScanSettings setCustomParameters(String parameters) {
        aiprojDocument.set("$.CustomParameters", parameters);
        return this;
    }

    @Override
    public DotNetSettings getDotNetSettings() {
        return DotNetSettings.builder()
                .solutionFile(fixSolutionFile(S("$.SolutionFile")))
                .webSiteFolder(S("$.WebSiteFolder"))
                .projectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(S("$.ProjectType"), DotNetSettings.ProjectType.NONE))
                .build();
    }

    @Override
    public JavaSettings getJavaSettings() {
        JavaParametersParseResult parseResult = parseJavaParameters(S("$.JavaParameters"));
        return JavaSettings.builder()
                .unpackUserPackages(B("$.IsUnpackUserPackages"))
                .userPackagePrefixes(null == parseResult ? null : parseResult.getPrefixes())
                .javaVersion(JavaVersion._0.value().equals(I("$.JavaVersion")) ? v1_8 : v1_11)
                .parameters(null == parseResult ? null : parseResult.getOther())
                .build();
    }

    @Override
    public @NonNull Boolean isSkipGitIgnoreFiles() {
        List<String> skipFilesFolders = O(aiprojDocument,"$.SkipFilesFolders");
        if (CollectionUtils.isEmpty(skipFilesFolders)) return false;
        return skipFilesFolders.contains(".gitignore");
    }

    @Override
    public @NonNull Boolean isUseSastRules() {
        log.trace("No custom SAST rules support for legacy AIPROJ schema");
        return false;
    }

    @Override
    public @NonNull Boolean isUseCustomPmRules() {
        log.trace("No custom PM rules support for legacy AIPROJ schema");
        return false;
    }

    @Override
    public @NonNull Boolean isUseCustomYaraRules() {
        return B("$.UseCustomYaraRules");
    }

    @Override
    public @NonNull Boolean isUseSecurityPolicies() {
        log.trace("No security policy support for legacy AIPROJ schema");
        return false;
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
    public Version getVersion() {
        return Version.LEGACY;
    }
}
