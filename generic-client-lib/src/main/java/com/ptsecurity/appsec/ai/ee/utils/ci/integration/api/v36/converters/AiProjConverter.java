package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.settings.v36.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ConverterHelper.initRemainingSettingsFields;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper.createObjectMapper;
import static org.joor.Reflect.on;

@Slf4j
public class AiProjConverter {
    private static final Map<AiProjScanSettings.BlackBoxScanLevel, BlackBoxScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new HashMap<>();
    private static final Map<AiProjScanSettings.Authentication.Item.Credentials.Type, AuthType> BLACKBOX_AUTH_TYPE_MAP = new HashMap<>();
    private static final Map<AiProjScanSettings.ProxySettings.Type, ProxyType> BLACKBOX_PROXY_TYPE_MAP = new HashMap<>();

    static {
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.NONE, BlackBoxScanLevel.None);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.FAST, BlackBoxScanLevel.Fast);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.NORMAL, BlackBoxScanLevel.Normal);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.FULL, BlackBoxScanLevel.Full);

        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.Authentication.Item.Credentials.Type.FORM, AuthType.Form);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.Authentication.Item.Credentials.Type.HTTP, AuthType.Http);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.Authentication.Item.Credentials.Type.NONE, AuthType.None);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.Authentication.Item.Credentials.Type.COOKIE, AuthType.RawCookie);

        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxySettings.Type.HTTP, ProxyType.Http);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxySettings.Type.HTTPNOCONNECT, ProxyType.HttpNoConnect);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxySettings.Type.SOCKS4, ProxyType.Socks4);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxySettings.Type.SOCKS5, ProxyType.Socks5);

    }

    protected static BlackBoxAuthentication fillAuthentication(@NonNull final BlackBoxAuthentication auth, @NonNull final AiProjScanSettings.Authentication jsonAuth) {
        AiProjScanSettings.Authentication.Item jsonItem = jsonAuth.getItem();
        if (null == jsonItem) return auth;

        AuthenticationItem authItem = new AuthenticationItem()
                .domain(jsonItem.getDomain())
                .formUrl(jsonItem.getFormUrl())
                .formXpath(jsonItem.getFormXPath())
                .testUrl(jsonItem.getTestUrl())
                .regexpOfSuccess(jsonItem.getRegexpOfSuccess());
        if (null != jsonItem.getCredentials()) {
            AuthenticationCredentials credentials = new AuthenticationCredentials()
                    .cookie(jsonItem.getCredentials().getCookie())
                    .type(BLACKBOX_AUTH_TYPE_MAP.get(jsonItem.getCredentials().getType()));
            if (null != jsonItem.getCredentials().getLogin()) {
                AiProjScanSettings.Authentication.Item.Credentials.Login jsonLogin = jsonItem.getCredentials().getLogin();
                credentials.login(new MappedAuthenticationObject()
                        .name(jsonLogin.getName())
                        .value(jsonLogin.getValue())
                        .isRegexp(jsonLogin.getRegexpUsed())
                        .regexp(jsonLogin.getRegexp())
                );
            }
            if (null != jsonItem.getCredentials().getPassword()) {
                AiProjScanSettings.Authentication.Item.Credentials.Password jsonPassword = jsonItem.getCredentials().getPassword();
                credentials.password(new MappedAuthenticationObject()
                        .name(jsonPassword.getName())
                        .value(jsonPassword.getValue())
                        .isRegexp(jsonPassword.getRegexpUsed())
                        .regexp(jsonPassword.getRegexp())
                );
            }
        }

        auth.setAuthItem(authItem);
        return auth;
    }

    protected static BlackBoxProxySettings convertProxySettings(final AiProjScanSettings.ProxySettings settings) {
        if (null == settings) return null;

        return new BlackBoxProxySettings()
                .host(settings.getHost())
                .port(settings.getPort())
                .username(settings.getUsername())
                .password(settings.getPassword())
                .isEnabled(settings.getIsEnabled())
                .type(BLACKBOX_PROXY_TYPE_MAP.get(settings.getType()));
    }

    public static V36ScanSettings convert(
            @NonNull AiProjScanSettings settings,
            @NonNull final List<String> defaultEnabledPatterns,
            @NonNull final List<String> defaultDisabledPatterns) {
        V36ScanSettings res = new V36ScanSettings();
        // PT AI server API creates invalid project scan settings if DisabledPatterns and EnabledPatterns are not defined (null)
        res.setDisabledPatterns(defaultDisabledPatterns);
        // As there's no enabled patterns in AIPROJ file, let's fill'em with default patterns
        res.setEnabledPatterns(defaultEnabledPatterns);

        res.setScanAppType(settings.getScanAppType());
        // Vulnerability search modules. Possible values are: Php, Java, CSharp, Configuration,
        // Fingerprint (includes DependencyCheck), PmTaint , BlackBox, JavaScript
        Set<AiProjScanSettings.ScanAppType> scanAppTypes = Arrays.stream(settings.getScanAppType().split("[, ]+"))
                .map(AiProjScanSettings.ScanAppType::from)
                .collect(Collectors.toSet());
        // Check if PHP / Java / C# modules are to be engaged
        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.PHP))
            fillCommonFields(res, settings);

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.JAVA)) {
            fillCommonFields(res, settings);
            res
                    .javaParameters(settings.getJavaParameters())
                    .javaVersion(0 == settings.getJavaVersion() ? JavaVersions.v1_8 : JavaVersions.v1_11)
                    .useJavaNormalizeVersionPattern(settings.getUseJavaNormalizeVersionPattern())
                    .javaNormalizeVersionPattern(settings.getJavaNormalizeVersionPattern());
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.CSHARP)) {
            fillCommonFields(res, settings);
            // In PT AI v.3.6 solution file is to be defined as "solution.sln" instead of "./solution.sln"
            String solutionFile = settings.getSolutionFile();
            do {
                if (StringUtils.isEmpty(solutionFile)) break;
                solutionFile = solutionFile.trim();
                if (!solutionFile.startsWith("./")) break;
                log.trace("Fix solution file name {}", solutionFile);
                solutionFile = solutionFile.substring("./".length());
                log.trace("Fixed solution file name is {}", solutionFile);
            } while (false);
            res
                    .projectType("Solution".equalsIgnoreCase(settings.getProjectType()) ? DotNetProjectType.Solution : DotNetProjectType.WebSite)
                    .solutionFile(solutionFile)
                    .webSiteFolder(settings.getWebSiteFolder());
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.CONFIGURATION)) {
            fillCommonFields(res, settings);
            // TODO: Check ignored configurationFiles as there's now such setting in aiproj JSON
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.FINGERPRINT)) {
            fillCommonFields(res, settings);
            res
                    .useDefaultFingerprints(settings.getUseDefaultFingerprints())
                    .useCustomYaraRules(settings.getUseCustomYaraRules());
            // TODO: Check ignored customYaraRules as for v3.6 it can be setup only via viewer

            // TODO: Check ignored isDependencyCheckAutoUpdateEnabled as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateBaseUrl as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateModifiedUrl as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckDataBaseFolder as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateRetireJsUrl as there's now such setting in aiproj JSON
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.PMTAINT)) {
            fillCommonFields(res, settings);
            res
                    .usePmAnalysis(settings.getUsePmAnalysis())
                    .useTaintAnalysis(settings.getUseTaintAnalysis());
            // User may have added custom disabled patterns. If those aren't disabled by language and may be enabled for this language, add'em
            if (null != settings.getDisabledPatterns())
                settings.getDisabledPatterns().stream()
                .filter(defaultEnabledPatterns::contains)
                .forEach(p -> Objects.requireNonNull(res.getDisabledPatterns()).add(p));
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.BLACKBOX)) {
            fillCommonFields(res, settings);
            res
                    .level(BLACKBOX_SCAN_LEVEL_MAP.get(settings.getBlackBoxScanLevel()))
                    .autocheckSite(settings.getAutocheckSite())
                    .customHeaders(settings.getCustomHeaders())
                    .autocheckCustomHeaders(settings.getAutocheckCustomHeaders());
            // TODO: Check ignored scanScope as there's now such setting in aiproj JSON
            // TODO: Check ignored configurationPath as there's now such setting in aiproj JSON
            // TODO: Check ignored bindAddress as there's now such setting in aiproj JSON

            AiProjScanSettings.Authentication jsonAuth = settings.getAuthentication();
            if (null != jsonAuth)
                res.authentication(fillAuthentication(new BlackBoxAuthentication(), jsonAuth));
            res.setProxySettings(convertProxySettings(settings.getProxySettings()));

            jsonAuth = settings.getAutocheckAuthentication();
            if (null != jsonAuth)
                res.autocheckAuthentication(fillAuthentication(new BlackBoxAuthentication(), jsonAuth));
            res.setAutocheckProxySettings(convertProxySettings(settings.getAutocheckProxySettings()));
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.JAVASCRIPT)) {
            fillCommonFields(res, settings);
            res
                    .javaScriptProjectFile(settings.getJavaScriptProjectFile())
                    .javaScriptProjectFolder(settings.getJavaScriptProjectFolder());
        }
        // PT AI server API creates unpredictable project scan settings if field values
        // are null and excluded from serialization. For example, missing useIssueTrackerIntegration
        // does enable Jira integration. So we need to explicitly set these field values to false
        initRemainingSettingsFields(res);
        return res;
    }

    /**
     * @param destination Instance of IJavaSettings, IPmTaintSettings etc. As v.3.6's definition
     *                    for these classes all contain big set of similar fields, to avoid lots of
     *                    "if-else" we will use reflection to set these fields
     * @param source Scan settings that were parsed from aiproj JSON file
     */
    protected static void fillCommonFields(@NonNull final Object destination, @NonNull final AiProjScanSettings source) {
        // As 12 out of 12 settings are share common set of 24 attributes,
        // let's fill'em using reflection
        on(destination).call("actualScanTarget", (String) null);
        on(destination).call("compressReport", source.getCompressReport());
        on(destination).call("considerPreviousScan", source.getConsiderPreviousScan());
        on(destination).call("customParameters", source.getCustomParameters());
        on(destination).call("disabledTypes", source.getDisabledTypes());
        on(destination).call("fullRescanOnNewFilesAdded", source.getFullRescanOnNewFilesAdded());
        on(destination).call("hideSuspectedVulnerabilities", source.getHideSuspectedVulnerabilities());

        // TODO: Check isBlackBoxScanEnabled as this field marked as read-only
        // on(settings).call("isBlackBoxScanEnabled", scanAppType.stream().anyMatch(t -> "BlackBox".equalsIgnoreCase(t)));
        // TODO: Check isStaticScanEnabled as this field marked as read-only
        // on(settings).call("isStaticScanEnabled", scanAppType.stream().anyMatch(t -> !"BlackBox".equalsIgnoreCase(t)));
        on(destination).call("preprocessingTimeout", source.getPreprocessingTimeout());
        on(destination).call("programmingLanguage", IssuesConverter.convert(source.getProgrammingLanguage()));

        on(destination).call("rootFolder", (String) null);
        on(destination).call("runAutocheckAfterScan", source.getRunAutocheckAfterScan());
        on(destination).call("scanTarget", (String) null);
        on(destination).call("scope", (String) null);
        on(destination).call("sendEmailWithReportsAfterScan", source.getSendEmailWithReportsAfterScan());
        on(destination).call("site", source.getSite());
        on(destination).call("skipFileFormats", source.getSkipFileFormats());
        on(destination).call("skipFilesFolders", source.getSkipFilesFolders());
        on(destination).call("tempDir", (String) null);
        on(destination).call("useIncrementalScan", source.getUseIncrementalScan());
        on(destination).call("useIssueTrackerIntegration", source.getUseIssueTrackerIntegration());

        // IBlackBoxSettings doesn't support some settings
        if (destination instanceof IBlackBoxSettings) return;
        // ICommonSettings doesn't support some settings
        if (destination instanceof ICommonSettings) return;

        on(destination).call("disableInterpretCores", false);
        on(destination).call("isDownloadDependencies", source.getIsDownloadDependencies());
        on(destination).call("isGraphEnabled", false);
        on(destination).call("isUnpackUserPackages", source.getIsUnpackUserPackages());
        on(destination).call("isUseEntryAnalysisPoint", source.getIsUseEntryAnalysisPoint());
        on(destination).call("isUsePublicAnalysisMethod", source.getIsUsePublicAnalysisMethod());
    }

    public static AiProjScanSettings verify(String json) throws GenericException {
        return call(() -> {
            ObjectMapper mapper = createObjectMapper();
            AiProjScanSettings res = mapper.readValue(json, AiProjScanSettings.class);
            if (StringUtils.isEmpty(res.getProjectName()))
                throw new IllegalArgumentException("ProjectName field is not defined or empty");
            if (null == res.getProgrammingLanguage())
                throw new IllegalArgumentException("ProgrammingLanguage field is not defined or empty");
            return res.fix();
        }, "JSON settings parse failed");
    }

    public static String serialize(AiProjScanSettings settings) throws GenericException {
        return call(
                () -> new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(settings.fix()),
                "JSON settings serialization failed");
    }

    /**
     * @param settingsJson JSON-defined AST settings
     * @return Minimized JSON-defined AST settings, i.e. without comments, formatting etc.
     * @throws GenericException
     */
    public static String minimize(@NonNull String settingsJson) throws GenericException {
        AiProjScanSettings settings = verify(settingsJson);
        return serialize(settings);
    }
}
