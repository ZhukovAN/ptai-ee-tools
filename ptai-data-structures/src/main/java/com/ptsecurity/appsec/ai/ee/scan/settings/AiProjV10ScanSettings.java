package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.networknt.schema.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.DotNetProjectType;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.JavaVersion;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.ProgrammingLanguage;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.blackbox.AuthType;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.blackbox.ProxyType;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.blackbox.ScanLevel;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.blackbox.ScanScope;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType.AUTO;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType.MANUAL;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_11;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_8;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static java.lang.String.CASE_INSENSITIVE_ORDER;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Slf4j
public class AiProjV10ScanSettings extends UnifiedAiProjScanSettings {
    private static final Map<String, ScanBrief.ScanSettings.Language> PROGRAMMING_LANGUAGE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, ScanModule> SCAN_MODULE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, UnifiedAiProjScanSettings.DotNetSettings.ProjectType> DOTNET_PROJECT_TYPE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, UnifiedAiProjScanSettings.JavaSettings.JavaVersion> JAVA_VERSION_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, BlackBoxSettings.ProxySettings.Type> BLACKBOX_PROXY_TYPE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, BlackBoxSettings.ScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
    private static final Map<String, BlackBoxSettings.ScanScope> BLACKBOX_SCAN_SCOPE_MAP = new TreeMap<>(CASE_INSENSITIVE_ORDER);
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

        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.ScanModule.CONFIGURATION.value(), ScanModule.CONFIGURATION);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.ScanModule.COMPONENTS.value(), ScanModule.COMPONENTS);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.ScanModule.BLACK_BOX.value(), ScanModule.BLACKBOX);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.ScanModule.PATTERN_MATCHING.value(), ScanModule.PATTERNMATCHING);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.ScanModule.DATA_FLOW_ANALYSIS.value(), ScanModule.DATAFLOWANALYSIS);
        SCAN_MODULE_MAP.put(com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v10.ScanModule.VULNERABLE_SOURCE_CODE.value(), ScanModule.VULNERABLESOURCECODE);

        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.NONE.value(), DotNetSettings.ProjectType.NONE);
        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.SOLUTION.value(), DotNetSettings.ProjectType.SOLUTION);
        DOTNET_PROJECT_TYPE_MAP.put(DotNetProjectType.WEB_SITE.value(), DotNetSettings.ProjectType.WEBSITE);

        JAVA_VERSION_MAP.put(JavaVersion.V_1_8.value(), v1_8);
        JAVA_VERSION_MAP.put(JavaVersion.V_1_11.value(), v1_11);

        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.HTTP.value(), BlackBoxSettings.ProxySettings.Type.HTTP);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.SOCKS_4.value(), BlackBoxSettings.ProxySettings.Type.SOCKS4);
        BLACKBOX_PROXY_TYPE_MAP.put(ProxyType.SOCKS_5.value(), BlackBoxSettings.ProxySettings.Type.SOCKS5);

        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NONE.value(), BlackBoxSettings.ScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FAST.value(), BlackBoxSettings.ScanLevel.FAST);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.FULL.value(), BlackBoxSettings.ScanLevel.FULL);
        BLACKBOX_SCAN_LEVEL_MAP.put(ScanLevel.NORMAL.value(), BlackBoxSettings.ScanLevel.NORMAL);

        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.PATH.value(), BlackBoxSettings.ScanScope.PATH);
        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.DOMAIN.value(), BlackBoxSettings.ScanScope.DOMAIN);
        BLACKBOX_SCAN_SCOPE_MAP.put(ScanScope.FOLDER.value(), BlackBoxSettings.ScanScope.FOLDER);

        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.NONE.value(), BlackBoxSettings.Authentication.Type.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.FORM.value(), BlackBoxSettings.Authentication.Type.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.RAW_COOKIE.value(), BlackBoxSettings.Authentication.Type.COOKIE);
        BLACKBOX_AUTH_TYPE_MAP.put(AuthType.HTTP.value(), BlackBoxSettings.Authentication.Type.HTTP);
    }

    @Override
    public @NonNull String getJsonSchema() {
        return ResourcesHelper.getResourceString("aiproj/schema/aiproj-v1.0.json");
    }

    @Override
    public Version getVersion() {
        return Version.V10;
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
    public UnifiedAiProjScanSettings setProgrammingLanguage(ScanBrief.ScanSettings.@NonNull Language value) {
        for (String language : PROGRAMMING_LANGUAGE_MAP.keySet()) {
            if (!PROGRAMMING_LANGUAGE_MAP.get(language).equals(value)) continue;
            aiprojDocument.set("$.ProgrammingLanguage", language);
        }
        return this;
    }

    @Override
    public Set<ScanModule> getScanModules() {
        Set<ScanModule> res = new HashSet<>();
        List<String> scanModules = O("$.ScanModules");
        for (String scanModule : scanModules)
            if (SCAN_MODULE_MAP.containsKey(scanModule)) res.add(SCAN_MODULE_MAP.get(scanModule));
        return res;
    }

    @Override
    public UnifiedAiProjScanSettings setScanModules(@NonNull Set<ScanModule> modules) {
        aiprojDocument.set("$.ScanModules", modules);
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
        if (null == O(aiprojDocument, "$.DotNetSettings")) return null;
        String solutionFile = S("$.DotNetSettings.SolutionFile");
        String projectType = S("$.DotNetSettings.ProjectType");
        return DotNetSettings.builder()
                .solutionFile(fixSolutionFile(solutionFile))
                .projectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(projectType, DotNetSettings.ProjectType.NONE))
                .build();
    }

    @Override
    public JavaSettings getJavaSettings() {
        if (null == O(aiprojDocument, "$.JavaSettings")) return null;
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
    public UnifiedAiProjScanSettings setUsePublicAnalysisMethod(@NonNull Boolean value) {
        aiprojDocument.set("$.UsePublicAnalysisMethod", value);
        return this;
    }

    @Override
    public @NonNull Boolean isUseSastRules() {
        return B("$.UseSastRules");
    }

    @Override
    public @NonNull Boolean isUseCustomPmRules() {
        throw GenericException.raise("No custom PM rules support for AIPROJ schema v.1.0", new UnsupportedOperationException());
    }

    @Override
    public @NonNull Boolean isUseCustomYaraRules() {
        return B("$.ComponentsSettings.UseCustomYaraRules");
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
    public UnifiedAiProjScanSettings setDownloadDependencies(@NonNull Boolean value) {
        aiprojDocument.set("$.DownloadDependencies", value);
        return this;
    }

    @Override
    public MailingProjectSettings getMailingProjectSettings() {
        log.trace("No mail notifications settings support for AIPROJ schema v.1.0");
        return null;
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
        if (null == auth) {
            log.info("Explicitly set authentication type NONE as there's no authentication settings defined");
            return BlackBoxSettings.Authentication.NONE;
        }
        BlackBoxSettings.Authentication.Type authType;
        authType = BLACKBOX_AUTH_TYPE_MAP.getOrDefault(S(auth, "$.Type"), BlackBoxSettings.Authentication.Type.NONE);

        if (BlackBoxSettings.Authentication.Type.FORM == authType) {
            Object form = O(auth, "$.Form");
            if (null == form) {
                log.info("Explicitly set authentication type NONE as there's no form authentication settings defined");
                return BlackBoxSettings.Authentication.NONE;
            }
            return BlackBoxSettings.FormAuthentication.builder()
                    .type(authType)
                    .detectionType(isEmpty(S(form, "$.FormXPath")) ? AUTO : MANUAL)
                    .loginKey(S(form, "$.LoginKey"))
                    .passwordKey(S(form, "$.PasswordKey"))
                    .login(S(form, "$.Login"))
                    .password(S(form, "$.Password"))
                    .formAddress(S(form, "$.FormAddress"))
                    .xPath(S(form, "$.FormXPath"))
                    .validationTemplate(S(form, "$.ValidationTemplate"))
                    .build();
        } else if (BlackBoxSettings.Authentication.Type.HTTP == authType) {
            Object http = O(auth, "$.Http");
            if (null == http) {
                log.info("Explicitly set authentication type NONE as there's no HTTP authentication settings defined");
                return BlackBoxSettings.Authentication.NONE;
            }
            return BlackBoxSettings.HttpAuthentication.builder()
                    .login(S(http, "$.Login"))
                    .password(S(http, "$.Password"))
                    .validationAddress(S(http, "$.ValidationAddress"))
                    .build();
        } else if (BlackBoxSettings.Authentication.Type.COOKIE == authType) {
            Object cookie = O(auth, "$.Cookie");
            if (null == cookie) {
                log.info("Explicitly set authentication type NONE as there's no cookie authentication settings defined");
                return BlackBoxSettings.Authentication.NONE;
            }
            return BlackBoxSettings.CookieAuthentication.builder()
                    .cookie(S(cookie, "$.Cookie"))
                    .validationAddress(S(cookie, "$.ValidationAddress"))
                    .validationTemplate(S(cookie, "$.ValidationTemplate"))
                    .build();
        } else
            return BlackBoxSettings.Authentication.NONE;
    }

    @Override
    public BlackBoxSettings getBlackBoxSettings() {
        if (!getScanModules().contains(ScanModule.BLACKBOX)) return null;
        Object blackBoxSettings = O("$.BlackBoxSettings");
        if (null == blackBoxSettings) return null;

        BlackBoxSettings res = new BlackBoxSettings();

        res.setScanLevel(BLACKBOX_SCAN_LEVEL_MAP.getOrDefault(S("$.BlackBoxSettings.Level"), BlackBoxSettings.ScanLevel.NONE));
        res.setRunAutocheckAfterScan(B(blackBoxSettings, "$.RunAutocheckAfterScan"));
        res.setSite(S(blackBoxSettings, "$.Site"));
        res.setScanScope(BLACKBOX_SCAN_SCOPE_MAP.getOrDefault(S("$.BlackBoxSettings.ScanScope"), BlackBoxSettings.ScanScope.PATH));

        Object proxySettings = O(blackBoxSettings, "$.ProxySettings");
        if (null != proxySettings)
            res.setProxySettings(convertProxySettings(proxySettings));

        Object authentication = O(blackBoxSettings, "$.Authentication");
        res.setAuthentication(convertAuthentication(authentication));

        return res;
    }
}
