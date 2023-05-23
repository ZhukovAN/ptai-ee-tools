package com.ptsecurity.appsec.ai.ee.scan.settings.v11;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.ptsecurity.appsec.ai.ee.helpers.aiproj.AiProjHelper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.BaseAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AuthItem;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.Authentication;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.DotNetProjectType;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.JavaVersion;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.ProgrammingLanguage;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.blackbox.AuthType;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.blackbox.ProxyType;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.blackbox.ScanLevel;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_11;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_8;
import static java.lang.String.CASE_INSENSITIVE_ORDER;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Slf4j
public class AiProjScanSettings extends BaseAiProjScanSettings implements UnifiedAiProjScanSettings {
    private static final Map<String, ScanBrief.ScanSettings.Language> PROGRAMMING_LANGUAGE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, ScanModule> SCAN_MODULE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, UnifiedAiProjScanSettings.DotNetSettings.ProjectType> DOTNET_PROJECT_TYPE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, UnifiedAiProjScanSettings.JavaSettings.JavaVersion> JAVA_VERSION_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, BlackBoxSettings.ProxySettings.Type> BLACKBOX_PROXY_TYPE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, BlackBoxSettings.ScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, BlackBoxSettings.Authentication.Type> BLACKBOX_AUTH_TYPE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);

    static {
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.JAVA.value(), ScanBrief.ScanSettings.Language.JAVA);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.C_SHARP.value(), ScanBrief.ScanSettings.Language.CSHARP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.VB.value(), ScanBrief.ScanSettings.Language.VB);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.PHP.value(), ScanBrief.ScanSettings.Language.PHP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.JAVA_SCRIPT.value(), ScanBrief.ScanSettings.Language.JAVASCRIPT);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.PYTHON.value(), ScanBrief.ScanSettings.Language.PYTHON);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.OBJECTIVE_C.value(), ScanBrief.ScanSettings.Language.OBJECTIVEC);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.SWIFT.value(), ScanBrief.ScanSettings.Language.SWIFT);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.C_AND_C_PLUS_PLUS.value(), ScanBrief.ScanSettings.Language.CPP);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.GO.value(), ScanBrief.ScanSettings.Language.GO);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.KOTLIN.value(), ScanBrief.ScanSettings.Language.KOTLIN);
        PROGRAMMING_LANGUAGE_MAP.put(ProgrammingLanguage.SQL.value(), ScanBrief.ScanSettings.Language.SQL);

        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.ScanModule.CONFIGURATION.value(), ScanModule.CONFIGURATION);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.ScanModule.COMPONENTS.value(), ScanModule.COMPONENTS);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.ScanModule.BLACK_BOX.value(), ScanModule.BLACKBOX);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.ScanModule.PATTERN_MATCHING.value(), ScanModule.PATTERNMATCHING);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.ScanModule.DATA_FLOW_ANALYSIS.value(), ScanModule.DATAFLOWANALYSIS);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.ScanModule.VULNERABLE_SOURCE_CODE.value(), ScanModule.VULNERABLESOURCECODE);

        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.NONE.value(), DotNetSettings.ProjectType.NONE);
        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.SOLUTION.value(), DotNetSettings.ProjectType.SOLUTION);
        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.WEB_SITE.value(), DotNetSettings.ProjectType.WEBSITE);

        JAVA_VERSION_MAP.put(JavaVersion.V_1_8.value(), v1_8);
        JAVA_VERSION_MAP.put(JavaVersion.V_1_11.value(), v1_11);

        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.HTTP.value(), BlackBoxSettings.ProxySettings.Type.HTTP);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.SOCKS_4.value(), BlackBoxSettings.ProxySettings.Type.SOCKS4);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.SOCKS_5.value(), BlackBoxSettings.ProxySettings.Type.SOCKS5);

        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NONE.value(), BlackBoxSettings.ScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FAST.value(), BlackBoxSettings.ScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FULL.value(), BlackBoxSettings.ScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NORMAL.value(), BlackBoxSettings.ScanLevel.NONE);

        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.NONE.value(), BlackBoxSettings.Authentication.Type.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.FORM.value(), BlackBoxSettings.Authentication.Type.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.RAW_COOKIE.value(), BlackBoxSettings.Authentication.Type.COOKIE);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.HTTP.value(), BlackBoxSettings.Authentication.Type.HTTP);
    }

    public UnifiedAiProjScanSettings load(@NonNull final String data) throws GenericException {
        aiprojDocument = Configuration.defaultConfiguration().jsonProvider().parse(data);
        return this;
    }

    @Override
    public Version getVersion() {
        return Version.V11;
    }

    @Override
    public @NonNull String getProjectName() {
        return S("$.ProjectName");
    }

    @Override
    public @NonNull ScanBrief.ScanSettings.Language getProgrammingLanguage() {
        return PROGRAMMING_LANGUAGE_MAP.get(S("$.ProgrammingLanguage"));
    }

    @Override
    public Set<ScanModule> getScanModules() {
        Set<ScanModule> res = new HashSet<>();
        List<String> scanModules = JsonPath.read(aiprojDocument, "$.ScanModules[*]");
        for (String scanModule : scanModules)
            if (SCAN_MODULE_MAP.containsKey(scanModule)) res.add(SCAN_MODULE_MAP.get(scanModule));
        return res;
    }

    @Override
    public String getCustomParameters() {
        return S("$.CustomParameters");
    }

    @Override
    public DotNetSettings getDotNetSettings() {
        if (null == JsonPath.read(aiprojDocument, "$.DotNetSettings")) return null;
        String solutionFile = S("$.DotNetSettings.SolutionFile");
        String projectType = S("$.DotNetSettings.ProjectType");
        return DotNetSettings.builder()
                .solutionFile(AiProjHelper.fixSolutionFile(solutionFile))
                .projectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(projectType, DotNetSettings.ProjectType.NONE))
                .build();
    }

    @Override
    public JavaSettings getJavaSettings() {
        if (null == JsonPath.read(aiprojDocument, "$.JavaSettings")) return null;
        return JavaSettings.builder()
                .unpackUserPackages(B("$.JavaSettings.UnpackUserPackages"))
                .userPackagePrefixes(S("$.JavaSettings.UserPackagePrefixes"))
                .javaVersion(JAVA_VERSION_MAP.getOrDefault(S("$.JavaSettings.Version"), v1_11))
                .parameters(S("$.JavaSettings.Parameters"))
                .build();
    }

    @Override
    public @NonNull Boolean isSkipGitIgnoreFiles() {
        return B("$.SkipGitIgnoreFiles");
    }

    @Override
    public @NonNull Boolean isUsePublicAnalysisMethod() {
        return B("$.UsePublicAnalysisMethod");
    }

    @Override
    public @NonNull Boolean isUseSastRules() {
        return B("$.UseSastRules");
    }

    @Override
    public @NonNull Boolean isUseCustomPmRules() {
        return B("$.UseCustomPmRules");
    }

    @Override
    public @NonNull Boolean isUseCustomYaraRules() {
        throw GenericException.raise("No custom SAST rules support for AIPROJ schema v.1.1", new UnsupportedOperationException());
    }

    @Override
    public @NonNull Boolean isUseSecurityPolicies() {
        return B("$.UseSecurityPolicies");
    }

    @Override
    public @NonNull Boolean isDownloadDependencies() {
        return B("$.DownloadDependencies");
    }

    @Override
    public MailingProjectSettings getMailingProjectSettings() {
        if (null == JsonPath.read(aiprojDocument, "$.MailingProjectSettings")) return null;
        return MailingProjectSettings.builder()
                .enabled(B("$.MailingProjectSettings.Enabled"))
                .mailProfileName(S("$.MailingProjectSettings.MailProfileName"))
                .emailRecipients(JsonPath.read(aiprojDocument, "$.MailingProjectSettings.EmailRecipients"))
                .build();
    }

    private BlackBoxSettings.ProxySettings convertProxySettings(@NonNull final Object proxySettings) {
        return BlackBoxSettings.ProxySettings.builder()
                .enabled(B(proxySettings, "$.Enabled"))
                .type(BLACKBOX_PROXY_TYPE_MAP.get(S(proxySettings, "$.Type")))
                .host(S(proxySettings, "$.Host"))
                .port(I(proxySettings, "$.Port"))
                .login(S(proxySettings, "$.Login"))
                .password(S(proxySettings, "$.Password"))
                .build();
    }

    private BlackBoxSettings.Authentication convertAuthentication(final Object auth) {
        log.trace("Check if AIPROJ authentication field is defined");
        if (null == auth)
            return new BlackBoxSettings.Authentication();
        BlackBoxSettings.Authentication.Type authType;
        authType = BLACKBOX_AUTH_TYPE_MAP.getOrDefault(S(auth, "$.Type"), BlackBoxSettings.Authentication.Type.NONE);

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
        if (null == JsonPath.read(aiprojDocument, "$.BlackBoxSettings")) return null;

        BlackBoxSettings blackBoxSettings = new BlackBoxSettings();

        blackBoxSettings.setScanLevel(BLACKBOX_SCAN_LEVEL_MAP.getOrDefault(S("$.BlackBoxSettings.Level"), BlackBoxSettings.ScanLevel.NONE));
        /*
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
        */
        return blackBoxSettings;
    }
}
