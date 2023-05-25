package com.ptsecurity.appsec.ai.ee.scan.settings.legacy;

import com.fasterxml.jackson.databind.JsonNode;
import com.jayway.jsonpath.Configuration;
import com.networknt.schema.*;
import com.ptsecurity.appsec.ai.ee.helpers.aiproj.AiProjHelper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AiprojLegacy;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AuthItem;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.Authentication;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.ProxySettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.DotNetProjectType;
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

import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_11;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_8;
import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.DotNetProjectType.SOLUTION;
import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.DotNetProjectType.WEB_SITE;
import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.legacy.DotNetProjectType.NONE;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static java.lang.Boolean.TRUE;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Slf4j
@SuppressWarnings({"deprecation"})
public class AiProjScanSettings extends AiprojLegacy implements UnifiedAiProjScanSettings {
    @Override
    public @NonNull String getProjectName() {
        return projectName;
    }

    @Override
    public ScanBrief.ScanSettings.@NonNull Language getProgrammingLanguage() {
        return PROGRAMMING_LANGUAGE_MAP.get(programmingLanguage);
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

    private static final Map<ProgrammingLanguage, ScanBrief.ScanSettings.Language> PROGRAMMING_LANGUAGE_MAP = new HashMap<>();
    private static final Map<DotNetProjectType, UnifiedAiProjScanSettings.DotNetSettings.ProjectType> DOTNET_PROJECT_TYPE_MAP = new HashMap<>();
    private static final Map<Integer, BlackBoxSettings.ProxySettings.Type> BLACKBOX_PROXY_TYPE_MAP = new HashMap<>();
    private static final Map<ScanLevel, BlackBoxSettings.ScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new HashMap<>();
    private static final Map<Integer, UnifiedAiProjScanSettings.BlackBoxSettings.Authentication.Type> BLACKBOX_AUTH_TYPE_MAP = new HashMap<>();


    static {
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.C_PLUS_PLUS, ScanBrief.ScanSettings.Language.CPP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.GO, ScanBrief.ScanSettings.Language.GO);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.JAVA_SCRIPT, ScanBrief.ScanSettings.Language.JAVASCRIPT);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.C_SHARP, ScanBrief.ScanSettings.Language.CSHARP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.JAVA, ScanBrief.ScanSettings.Language.JAVA);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.KOTLIN, ScanBrief.ScanSettings.Language.KOTLIN);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.SQL, ScanBrief.ScanSettings.Language.SQL);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.PYTHON, ScanBrief.ScanSettings.Language.PYTHON);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.SWIFT, ScanBrief.ScanSettings.Language.SWIFT);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.VB, ScanBrief.ScanSettings.Language.VB);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.PHP, ScanBrief.ScanSettings.Language.PHP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.OBJECTIVE_C, ScanBrief.ScanSettings.Language.OBJECTIVEC);

        DOTNET_PROJECT_TYPE_MAP.put(NONE, DotNetSettings.ProjectType.NONE);
        DOTNET_PROJECT_TYPE_MAP.put(SOLUTION, DotNetSettings.ProjectType.SOLUTION);
        DOTNET_PROJECT_TYPE_MAP.put(WEB_SITE, DotNetSettings.ProjectType.WEBSITE);

        BLACKBOX_PROXY_TYPE_MAP.put(0, BlackBoxSettings.ProxySettings.Type.HTTP);
        BLACKBOX_PROXY_TYPE_MAP.put(1, BlackBoxSettings.ProxySettings.Type.HTTPNOCONNECT);
        BLACKBOX_PROXY_TYPE_MAP.put(2, BlackBoxSettings.ProxySettings.Type.SOCKS4);
        BLACKBOX_PROXY_TYPE_MAP.put(3, BlackBoxSettings.ProxySettings.Type.SOCKS5);

        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NONE, BlackBoxSettings.ScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FAST, BlackBoxSettings.ScanLevel.FAST);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NORMAL, BlackBoxSettings.ScanLevel.NORMAL);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FULL, BlackBoxSettings.ScanLevel.FULL);

        BLACKBOX_AUTH_TYPE_MAP.put(0, BlackBoxSettings.Authentication.Type.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(1, BlackBoxSettings.Authentication.Type.HTTP);
        BLACKBOX_AUTH_TYPE_MAP.put(2, BlackBoxSettings.Authentication.Type.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(3, BlackBoxSettings.Authentication.Type.COOKIE);
    }

    @Override
    public Set<ScanModule> getScanModules() {
        Set<ScanModule> res = new HashSet<>();
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
                && TRUE.equals(useTaintAnalysis);
        if (abstractInterpretationCoreUsed || taintOnlyLanguageUsed) res.add(ScanModule.VULNERABLESOURCECODE);
        if (TRUE.equals(useTaintAnalysis) && scanAppTypes.contains(ScanAppType.PMTAINT))
            res.add(ScanModule.DATAFLOWANALYSIS);
        if (TRUE.equals(usePmAnalysis) && scanAppTypes.contains(ScanAppType.PMTAINT))
            res.add(ScanModule.PATTERNMATCHING);
        if (scanAppTypes.contains(ScanAppType.CONFIGURATION)) res.add(ScanModule.CONFIGURATION);
        if (scanAppTypes.contains(ScanAppType.BLACKBOX)) res.add(ScanModule.BLACKBOX);
        if (scanAppTypes.contains(ScanAppType.DEPENDENCYCHECK) || scanAppTypes.contains(ScanAppType.FINGERPRINT))
            res.add(ScanModule.COMPONENTS);
        return res;
    }

    private BlackBoxSettings.ProxySettings convert(@NonNull final ProxySettings proxySettings) {
        return BlackBoxSettings.ProxySettings.builder()
                .enabled(TRUE.equals(proxySettings.isEnabled))
                .type(BLACKBOX_PROXY_TYPE_MAP.get(proxySettings.type))
                .host(proxySettings.host)
                .port(proxySettings.port)
                .login(proxySettings.username)
                .password(proxySettings.password)
                .build();
    }

    private BlackBoxSettings.Authentication convert(final Authentication authentication) {
        log.trace("Check if AIPROJ authentication field is defined");
        if (null == authentication || null == authentication.authItem || null == authentication.authItem.credentials)
            return new BlackBoxSettings.Authentication();
        @NonNull AuthItem authItem = authentication.authItem;
        BlackBoxSettings.Authentication.Type authType = BLACKBOX_AUTH_TYPE_MAP.getOrDefault(authItem.credentials.type, BlackBoxSettings.Authentication.Type.NONE);

        if (BlackBoxSettings.Authentication.Type.FORM == authType)
            return isEmpty(authItem.formXpath)
                    ? BlackBoxSettings.FormAuthenticationAuto.builder()
                    .type(authType)
                    .formAddress(authItem.formUrl)
                    .login(null != authItem.credentials.login ? authItem.credentials.login.value : null)
                    .password(null != authItem.credentials.password ? authItem.credentials.password.value : null)
                    .validationTemplate(authItem.regexpOfSuccess)
                    .build()
                    : BlackBoxSettings.FormAuthenticationManual.builder()
                    .type(authType)
                    .formAddress(authItem.formUrl)
                    .xPath(authItem.formXpath)
                    .loginKey(null != authItem.credentials.login ? authItem.credentials.login.name : null)
                    .login(null != authItem.credentials.login ? authItem.credentials.login.value : null)
                    .passwordKey(null != authItem.credentials.password ? authItem.credentials.password.name : null)
                    .password(null != authItem.credentials.password ? authItem.credentials.password.value : null)
                    .validationTemplate(authItem.regexpOfSuccess)
                    .build();
        else if (BlackBoxSettings.Authentication.Type.HTTP == authType)
            return BlackBoxSettings.HttpAuthentication.builder()
                    .login(null != authItem.credentials.login ? authItem.credentials.login.value : null)
                    .password(null != authItem.credentials.password ? authItem.credentials.password.value : null)
                    .validationAddress(authItem.testUrl)
                    .build();
        else if (BlackBoxSettings.Authentication.Type.COOKIE == authType)
            return BlackBoxSettings.CookieAuthentication.builder()
                    .cookie(authItem.credentials.cookie)
                    .validationAddress(authItem.testUrl)
                    .validationTemplate(authItem.regexpOfSuccess)
                    .build();
        else
            return new BlackBoxSettings.Authentication();
    }

    private List<Pair<String, String>> convert(@NonNull final List<List<String>> headers) {
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

        if (null != level) blackBoxSettings.setScanLevel(BLACKBOX_SCAN_LEVEL_MAP.get(level));
        blackBoxSettings.setRunAutocheckAfterScan(TRUE.equals(runAutocheckAfterScan));

        blackBoxSettings.setSite(site);
        if (null != proxySettings)
            blackBoxSettings.setProxySettings(convert(proxySettings));
        if (null != customHeaders)
            blackBoxSettings.setHttpHeaders(convert(customHeaders));
        if (null != authentication)
            blackBoxSettings.setAuthentication(convert(authentication));

        if (!blackBoxSettings.getRunAutocheckAfterScan()) return blackBoxSettings;

        blackBoxSettings.setAutocheckSite(autocheckSite);
        if (null != autocheckProxySettings)
            blackBoxSettings.setAutocheckProxySettings(convert(autocheckProxySettings));
        if (null != autocheckCustomHeaders)
            blackBoxSettings.setAutocheckHttpHeaders(convert(autocheckCustomHeaders));
        if (null != this.autocheckAuthentication)
            blackBoxSettings.setAutocheckAuthentication(convert(autocheckAuthentication));
        return blackBoxSettings;
    }

    @Override
    public @NonNull Boolean isDownloadDependencies() {
        return TRUE.equals(isDownloadDependencies);
    }

    @Override
    public @NonNull Boolean isUsePublicAnalysisMethod() {
        return TRUE.equals(isUsePublicAnalysisMethod);
    }

    @Override
    public String getCustomParameters() {
        return customParameters;
    }

    @Override
    public DotNetSettings getDotNetSettings() {
        return DotNetSettings.builder()
                .solutionFile(AiProjHelper.fixSolutionFile(solutionFile))
                .webSiteFolder(webSiteFolder)
                .projectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(projectType, DotNetSettings.ProjectType.NONE))
                .build();
    }

    @Override
    public JavaSettings getJavaSettings() {
        AiProjHelper.JavaParametersParseResult parseResult = AiProjHelper.parseJavaParameters(javaParameters);
        return JavaSettings.builder()
                .unpackUserPackages(TRUE.equals(isUnpackUserPackages))
                .userPackagePrefixes(null == parseResult ? null : parseResult.getPrefixes())
                .javaVersion(JavaVersion._0.equals(javaVersion) ? v1_8 : v1_11)
                .parameters(null == parseResult ? null : parseResult.getOther())
                .build();
    }

    @Override
    public @NonNull Boolean isSkipGitIgnoreFiles() {
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
        return TRUE.equals(useCustomYaraRules);
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
    public UnifiedAiProjScanSettings load(@NonNull String data) throws GenericException {
        return call(() -> {
            String schema = ResourcesHelper.getResourceString("aiproj/schema/aiproj-legacy.json");
            JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4);
            JsonSchema jsonSchema = factory.getSchema(schema);
            JsonNode jsonNode = createObjectMapper().readTree(data);
            Set<ValidationMessage> errors = jsonSchema.validate(jsonNode);
            if (CollectionUtils.isNotEmpty(errors)) {
                log.debug("AIPROJ parse errors:");
                for (ValidationMessage error : errors)
                    log.debug(error.getMessage());
                throw GenericException.raise("AIPROJ schema validation failed", new JsonSchemaException(errors.toString()));
            }
            return createObjectMapper().readValue(data, AiProjScanSettings.class);

        }, "AIPROJ parse failed");
    }

    @Override
    public Version getVersion() {
        return Version.LEGACY;
    }
}
