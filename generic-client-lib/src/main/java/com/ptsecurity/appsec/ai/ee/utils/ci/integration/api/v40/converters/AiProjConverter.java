package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.converters;

import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v40.legacy.model.*;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ConverterHelper.initRemainingSettingsFields;

@Slf4j
public class AiProjConverter {
    private static final Map<AiProjScanSettings.BlackBoxScanLevel, BlackBoxScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new HashMap<>();
    private static final Map<AiProjScanSettings.CredentialsType, AuthType> BLACKBOX_AUTH_TYPE_MAP = new HashMap<>();
    private static final Map<AiProjScanSettings.ProxyType, ProxyType> BLACKBOX_PROXY_TYPE_MAP = new HashMap<>();

    static {
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.NONE, BlackBoxScanLevel.None);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.FAST, BlackBoxScanLevel.Fast);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.NORMAL, BlackBoxScanLevel.Normal);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.FULL, BlackBoxScanLevel.Full);

        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.CredentialsType.FORM, AuthType.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.CredentialsType.HTTP, AuthType.HTTP);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.CredentialsType.NONE, AuthType.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.CredentialsType.COOKIE, AuthType.RAWCOOKIE);

        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxyType.HTTP, ProxyType.HTTP);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxyType.HTTPNOCONNECT, ProxyType.HTTPNOCONNECT);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxyType.SOCKS4, ProxyType.SOCKS4);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxyType.SOCKS5, ProxyType.SOCKS5);
    }

    protected static BlackBoxAuthentication fillAuthentication(@NonNull final BlackBoxAuthentication auth, @NonNull final AiProjScanSettings.Authentication jsonAuth) {
        AiProjScanSettings.AuthItem jsonAuthItem = jsonAuth.getAuthItem();
        if (null == jsonAuthItem) return auth;

        AuthenticationItem authItem = new AuthenticationItem()
                .domain(jsonAuthItem.getDomain())
                .formUrl(jsonAuthItem.getFormUrl())
                .formXpath(jsonAuthItem.getFormXPath())
                .testUrl(jsonAuthItem.getTestUrl())
                .regexpOfSuccess(jsonAuthItem.getRegexpOfSuccess());
        if (null != jsonAuthItem.getCredentials()) {
            AuthenticationCredentials credentials = new AuthenticationCredentials()
                    .cookie(jsonAuthItem.getCredentials().getCookie())
                    .type(BLACKBOX_AUTH_TYPE_MAP.get(jsonAuthItem.getCredentials().getType()));
            if (null != jsonAuthItem.getCredentials().getLogin()) {
                AiProjScanSettings.Login jsonLogin = jsonAuthItem.getCredentials().getLogin();
                credentials.login(new MappedAuthenticationObject()
                        .name(jsonLogin.getName())
                        .value(jsonLogin.getValue())
                        .isRegexp(jsonLogin.getRegexpUsed())
                        .regexp(jsonLogin.getRegexp())
                );
            }
            if (null != jsonAuthItem.getCredentials().getPassword()) {
                AiProjScanSettings.Password jsonPassword = jsonAuthItem.getCredentials().getPassword();
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

    public static V40ScanSettings convert(
            @NonNull AiProjScanSettings settings,
            @NonNull final List<String> defaultEnabledPatterns,
            @NonNull final List<String> defaultDisabledPatterns) {
        V40ScanSettings res = new V40ScanSettings();
        // PT AI server API creates invalid project scan settings if DisabledPatterns and EnabledPatterns are not defined (null)
        res.setDisabledPatterns(defaultDisabledPatterns);
        // As there's no enabled patterns in AIPROJ file, let's fill them with default patterns
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
                    .javaVersion(0 == settings.getJavaVersion() ? JavaVersions.v1_8 : JavaVersions.v1_11);
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.CSHARP)) {
            fillCommonFields(res, settings);
            res
                    .projectType("Solution".equalsIgnoreCase(settings.getProjectType()) ? DotNetProjectType.Solution : DotNetProjectType.WebSite)
                    .solutionFile(settings.getSolutionFile())
                    .webSiteFolder(settings.getWebSiteFolder());
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.CONFIGURATION))
            fillCommonFields(res, settings);

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
            res.proxySettings(convertProxySettings(settings.getProxySettings()));

            jsonAuth = settings.getAutocheckAuthentication();
            if (null != jsonAuth)
                res.autocheckAuthentication(fillAuthentication(new BlackBoxAuthentication(), jsonAuth));
            res.autocheckProxySettings(convertProxySettings(settings.getAutocheckProxySettings()));
        }

        if (scanAppTypes.contains(AiProjScanSettings.ScanAppType.JAVASCRIPT))
            fillCommonFields(res, settings);
        // PT AI server API creates unpredictable project scan settings if field values
        // are null and excluded from serialization. For example, missing useIssueTrackerIntegration
        // does enable Jira integration. So we need to explicitly set these field values to false
        initRemainingSettingsFields(res);
        return res;
    }

    @NonNull
    public static BaseProjectSettingsModel convertBaseProjectSettings(
            @NonNull AiProjScanSettings settings) {
        BaseProjectSettingsModel result = new BaseProjectSettingsModel();

        log.trace("Set base project settings");
        result.setName(settings.getProjectName());
        result.setProgrammingLanguageGroup(IssuesConverter.convertLanguageGroup(settings.getProgrammingLanguage()));
        result.setProjectUrl(settings.getSite());

        result.setWhiteBox(convertWhiteBoxSettings(settings));

        // Vulnerability search modules. Possible values are: Php, Java, CSharp, Configuration,
        // Fingerprint (includes DependencyCheck), PmTaint , BlackBox, JavaScript
        Set<AiProjScanSettings.ScanAppType> scanAppTypes = Arrays.stream(settings.getScanAppType().split("[, ]+"))
                .map(AiProjScanSettings.ScanAppType::from)
                .collect(Collectors.toSet());
        result.setBlackBoxEnabled(scanAppTypes.contains(AiProjScanSettings.ScanAppType.BLACKBOX));
        if (Boolean.TRUE.equals(result.getBlackBoxEnabled())) {
            log.trace("Set base project blackbox settings");
            result.setBlackBox(convertBlackBoxSettings(settings));
        }

        return result;
    }

    /**
     * @param destination Instance of IJavaSettings, IPmTaintSettings etc. As v.3.6's definition
     *                    for these classes all contain big set of similar fields, to avoid lots of
     *                    "if-else" we will use reflection to set these fields
     * @param source Scan settings that were parsed from aiproj JSON file
     */
    protected static void fillCommonFields(@NonNull final V40ScanSettings destination, @NonNull final AiProjScanSettings source) {
        destination
                .actualScanTarget(null)
                .compressReport(source.getCompressReport())
                .considerPreviousScan(source.getConsiderPreviousScan())
                .customParameters(source.getCustomParameters())
                .disabledTypes(source.getDisabledTypes())
                .fullRescanOnNewFilesAdded(source.getFullRescanOnNewFilesAdded())
                .hideSuspectedVulnerabilities(source.getHideSuspectedVulnerabilities())
                .preprocessingTimeout(source.getPreprocessingTimeout())
                .programmingLanguage(IssuesConverter.convertLanguage(source.getProgrammingLanguage()))
                .rootFolder(null)
                .runAutocheckAfterScan(source.getRunAutocheckAfterScan())
                .scanTarget(null)
                .scope(null)
                .sendEmailWithReportsAfterScan(source.getSendEmailWithReportsAfterScan())
                .site(source.getSite())
                .skipFileFormats(source.getSkipFileFormats())
                .skipFilesFolders(source.getSkipFilesFolders())
                .tempDir(null)
                .useIncrementalScan(source.getUseIncrementalScan())
                .useIssueTrackerIntegration(source.getUseIssueTrackerIntegration())
                .disableInterpretCores(false)
                .isDownloadDependencies(source.getIsDownloadDependencies())
                .isGraphEnabled(false)
                .isUnpackUserPackages(source.getIsUnpackUserPackages())
                .isUseEntryAnalysisPoint(source.getIsUseEntryAnalysisPoint())
                .isUsePublicAnalysisMethod(source.getIsUsePublicAnalysisMethod());
    }

    public static ExtendedBlackBoxSettingsModel convertExtendedBlackBoxSettings(@NonNull final AiProjScanSettings settings) {
        Set<AiProjScanSettings.ScanAppType> scanAppTypes = Arrays.stream(settings.getScanAppType().split("[, ]+"))
                .map(AiProjScanSettings.ScanAppType::from)
                .collect(Collectors.toSet());
        if (!scanAppTypes.contains(AiProjScanSettings.ScanAppType.BLACKBOX)) return null;
        ExtendedBlackBoxSettingsModel result = new ExtendedBlackBoxSettingsModel();
        result.setHost(settings.getSite());
        result.setRunAutocheckAfterScan(settings.getRunAutocheckAfterScan());
        result.setIsActive(true);
        result.setScanLevel(BLACKBOX_SCAN_LEVEL_MAP.get(settings.getBlackBoxScanLevel()));
        // TODO: Check ignored scanScope as there's now such setting in aiproj JSON
        if (null != settings.getCustomHeaders()) {
            log.trace("Set additional HTTP headers");
            List<AdditionalHttpHeader> headers = new ArrayList<>();
            for (List<String> header : settings.getCustomHeaders()) {
                if (2 != header.size()) continue;
                headers.add(new AdditionalHttpHeader().key(header.get(0)).value(header.get(1)));
            }
            result.setAdditionalHttpHeaders(headers);
        }
        return result;
    }

    protected static WhiteBoxSettingsModel convertWhiteBoxSettings(@NonNull final AiProjScanSettings settings) {
        WhiteBoxSettingsModel result = new WhiteBoxSettingsModel();

        log.trace("Parse AIPROJ vulnerability search modules list");
        // Vulnerability search modules. Possible values are: Php, Java, CSharp, Configuration,
        // Fingerprint (includes DependencyCheck), PmTaint , BlackBox, JavaScript
        Set<AiProjScanSettings.ScanAppType> scanAppTypes = Arrays.stream(settings.getScanAppType().split("[, ]+"))
                .map(AiProjScanSettings.ScanAppType::from)
                .collect(Collectors.toSet());

        log.trace("Set base project whitebox settings");
        // Check if PHP / Java / C# / JavaScript modules are to be engaged
        final Set<AiProjScanSettings.ScanAppType> abstractInterpretationEngines = new HashSet<>(Arrays.asList(AiProjScanSettings.ScanAppType.PHP, AiProjScanSettings.ScanAppType.JAVA, AiProjScanSettings.ScanAppType.CSHARP, AiProjScanSettings.ScanAppType.JAVASCRIPT));
        result.setSearchForVulnerableSourceCodeEnabled(scanAppTypes.stream().anyMatch(abstractInterpretationEngines::contains));
        result.setDataFlowAnalysisEnabled(settings.getUseTaintAnalysis() && scanAppTypes.contains(AiProjScanSettings.ScanAppType.PMTAINT));
        result.setPatternMatchingEnabled(settings.getUsePmAnalysis() && scanAppTypes.contains(AiProjScanSettings.ScanAppType.PMTAINT));
        result.setSearchForConfigurationFlawsEnabled(scanAppTypes.contains(AiProjScanSettings.ScanAppType.CONFIGURATION));
        result.setSearchForVulnerableComponentsEnabled(scanAppTypes.contains(AiProjScanSettings.ScanAppType.FINGERPRINT));

        return result;
    }

    protected static BlackBoxSettingsModel convertBlackBoxSettings(@NonNull final AiProjScanSettings settings) {
        BlackBoxSettingsModel result = new BlackBoxSettingsModel();
        result.setAuthentication(AuthType.NONE);

        log.trace("Check if AIPROJ authentication field is defined");
        if (null == settings.getAuthentication()) return result;
        AiProjScanSettings.AuthItem jsonAuth = settings.getAuthentication().getAuthItem();
        if (null == jsonAuth) return result;

        result.setDomainName(jsonAuth.getDomain());
        result.setFormUrl(jsonAuth.getFormUrl());
        result.setFormXpath(jsonAuth.getFormXPath());
        result.setTestUrl(jsonAuth.getTestUrl());
        result.setValidationRegexTemplate(jsonAuth.getRegexpOfSuccess());


        if (null == jsonAuth.getCredentials()) return result;

        result.setAuthentication(BLACKBOX_AUTH_TYPE_MAP.getOrDefault(jsonAuth.getCredentials().getType(), AuthType.NONE));
        if (AuthType.RAWCOOKIE.equals(result.getAuthentication())) {
            log.trace("Set cookie authentication");
            if (null != jsonAuth.getCredentials())
                result.setCookie(jsonAuth.getCredentials().getCookie());
        } else if (AuthType.FORM.equals(result.getAuthentication())) {
            log.trace("Set form authentication");
            if (null != jsonAuth.getCredentials()) {
                if (null != jsonAuth.getCredentials().getLogin()) {
                    result.setLoginKey(jsonAuth.getCredentials().getLogin().getName());
                    result.setLogin(jsonAuth.getCredentials().getLogin().getValue());
                }
                if (null != jsonAuth.getCredentials().getPassword()) {
                    result.setPasswordKey(jsonAuth.getCredentials().getPassword().getName());
                    result.setPassword(jsonAuth.getCredentials().getPassword().getValue());
                }
            }
        } else if (AuthType.HTTP.equals(result.getAuthentication())) {
            log.trace("Set HTTP authentication");
            if (null != jsonAuth.getCredentials()) {
                if (null != jsonAuth.getCredentials().getLogin())
                    result.setLogin(jsonAuth.getCredentials().getLogin().getValue());
                if (null != jsonAuth.getCredentials().getPassword())
                    result.setPassword(jsonAuth.getCredentials().getPassword().getValue());
            }
        }

        result.setRunAutocheckAfterScan(settings.getRunAutocheckAfterScan());
        return result;
    }
}
