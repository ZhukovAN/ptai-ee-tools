package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters;

import com.google.gson.annotations.SerializedName;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.*;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ClassUtils;

import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

import static org.joor.Reflect.on;

@Slf4j
public class AiProjConverter {
    private static final Map<AiProjScanSettings.BlackBoxScanLevel, BlackBoxScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new HashMap<>();

    static {
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.NONE, BlackBoxScanLevel.None);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.FAST, BlackBoxScanLevel.Fast);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.NORMAL, BlackBoxScanLevel.Normal);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.FULL, BlackBoxScanLevel.Full);
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
                    .cookie(jsonAuthItem.getCredentials().getCookie());
            if (AiProjScanSettings.CredentialsType.FORM.equals(jsonAuthItem.getCredentials().getType()))
                credentials.setType(AuthType.Form);
            else if (AiProjScanSettings.CredentialsType.HTTP.equals(jsonAuthItem.getCredentials().getType()))
                credentials.setType(AuthType.Http);
            else if (AiProjScanSettings.CredentialsType.NONE.equals(jsonAuthItem.getCredentials().getType()))
                credentials.setType(AuthType.None);
            else if (AiProjScanSettings.CredentialsType.COOKIE.equals(jsonAuthItem.getCredentials().getType()))
                credentials.setType(AuthType.RawCookie);
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

    protected static BlackBoxProxySettings fillProxy(@NonNull final BlackBoxProxySettings proxy, @NonNull final AiProjScanSettings.ProxySettings jsonProxy) {
        proxy.host(jsonProxy.getHost())
                .port(jsonProxy.getPort())
                .username(jsonProxy.getUsername())
                .password(jsonProxy.getPassword())
                .isEnabled(jsonProxy.getIsEnabled());

        if (null != jsonProxy.getType()) {
            AiProjScanSettings.ProxyType jsonType = jsonProxy.getType();
            if (AiProjScanSettings.ProxyType.HTTP.equals(jsonType))
                proxy.setType(ProxyType.Http);
            else if (AiProjScanSettings.ProxyType.HTTPNOCONNECT.equals(jsonType))
                proxy.setType(ProxyType.HttpNoConnect);
            else if (AiProjScanSettings.ProxyType.SOCKS4.equals(jsonType))
                proxy.setType(ProxyType.Socks4);
            else if (AiProjScanSettings.ProxyType.SOCKS5.equals(jsonType))
                proxy.setType(ProxyType.Socks5);
        }

        return proxy;
    }

    /**
     * Method hierarchically searches Boolean fields annotated
     * as SerializedName and sets them to false
     * @param object Object instance to init
     */
    @SneakyThrows
    public static void initRemainingSettingsFields(final Object object) {
        if (null == object) return;
        Class<?> c = object.getClass();
        // Iterate through class hierarchy
        while (null != c) {
            // Init fields annotated with @SerializedName
            for (Field field : c.getDeclaredFields()) {
                if (!field.isAnnotationPresent(SerializedName.class)) continue;
                initField(object, field);
            }
            c = c.getSuperclass();
        }
    }

    /**
     * If field is of Boolean type, set its value to false. Iterate
     * through its nested fields otherwise and set them in the same manner
     * @param object Object instance field belongs to
     * @param field Field that value is to be initialized
     */
    @SneakyThrows
    protected static void initField(final Object object, final Field field) {
        if (null == field) return;
        Class<?> c = field.getType();
        if (ClassUtils.isPrimitiveWrapper(c) && Boolean.class.equals(c))
            if (null == on(object).field(field.getName()).get())
                on(object).set(field.getName(), false);
        else
            initRemainingSettingsFields(on(object).field(field.getName()).get());
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
            res
                    .projectType("Solution".equalsIgnoreCase(settings.getProjectType()) ? DotNetProjectType.Solution : DotNetProjectType.WebSite)
                    .solutionFile(settings.getSolutionFile())
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
            AiProjScanSettings.ProxySettings jsonProxy = settings.getProxySettings();
            if (null != jsonProxy)
                res.proxySettings(fillProxy(new BlackBoxProxySettings(), jsonProxy));

            jsonAuth = settings.getAutocheckAuthentication();
            if (null != jsonAuth)
                res.autocheckAuthentication(fillAuthentication(new BlackBoxAuthentication(), jsonAuth));
            jsonProxy = settings.getAutocheckProxySettings();
            if (null != jsonProxy)
                res.autocheckProxySettings(fillProxy(new BlackBoxProxySettings(), jsonProxy));
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
}
