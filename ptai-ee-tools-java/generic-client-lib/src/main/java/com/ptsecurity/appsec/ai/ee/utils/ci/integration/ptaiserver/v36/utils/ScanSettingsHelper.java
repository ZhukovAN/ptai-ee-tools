package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings.ProgrammingLanguage.JAVA;
import static org.joor.Reflect.on;

/**
 * This class is to be used as a helper utility to fill over-complicated IScanSettings
 * instance. IScanSettings type was to be used in PT AI REST API, but due to some reasons v.3.6
 * contains simplified model where API methods like getting existing project scan settings return
 * JSON that looks like a product of multiple inherited interfaces like IJavaSettings, IPmTaintSettings etc.
 * So it contains all the attributes of these interfaces. Unfortunately, v.3.6 OpenAPI description
 * contain errors, so I had to manually add V36ScanSettings type that is to be used for v.3.6
 */
public class ScanSettingsHelper {
    /**
     * @param settings Instance of IJavaSettings, IPmTaintSettings etc. As v.3.6's definition
     *                 for these classes all contain big set of similar fields, to avoid lots of
     *                 "if-else" we will use reflection to set these fields
     * @param json Scan settings that were parsed from aiproj JSON file
     */
    protected void fillCommonFields(@NonNull final Object settings, @NonNull final ScanSettings json) {
        // As 12 out of 12 settings are share common set of 24 attributes,
        // let's fill'em using reflection
        on(settings).call("actualScanTarget", (String) null);
        on(settings).call("compressReport", json.isCompressReport());
        on(settings).call("considerPreviousScan", json.isConsiderPreviousScan());
        on(settings).call("customParameters", json.getCustomParameters());
        on(settings).call("disabledTypes", json.getDisabledTypes());
        on(settings).call("fullRescanOnNewFilesAdded", json.isFullRescanOnNewFilesAdded());
        on(settings).call("hideSuspectedVulnerabilities", json.isHideSuspectedVulnerabilities());

        List<String> scanAppType = Arrays.stream(json.getScanAppType().split("[, ]+"))
                .map(t -> t.trim()).collect(Collectors.toList());
        // TODO: Check isBlackBoxScanEnabled as this field marked as read-only
        // on(settings).call("isBlackBoxScanEnabled", scanAppType.stream().anyMatch(t -> "BlackBox".equalsIgnoreCase(t)));
        // TODO: Check isStaticScanEnabled as this field marked as read-only
        // on(settings).call("isStaticScanEnabled", scanAppType.stream().anyMatch(t -> !"BlackBox".equalsIgnoreCase(t)));
        on(settings).call("preprocessingTimeout", json.getPreprocessingTimeout());
        on(settings).call("programmingLanguage", getProgrammingLanguageV36(json.getProgrammingLanguage()));

        on(settings).call("rootFolder", (String) null);
        on(settings).call("runAutocheckAfterScan", json.isRunAutocheckAfterScan());
        on(settings).call("scanTarget", (String) null);
        on(settings).call("scope", (String) null);
        on(settings).call("sendEmailWithReportsAfterScan", json.isSendEmailWithReportsAfterScan());
        on(settings).call("site", json.getSite());
        on(settings).call("skipFileFormats", json.getSkipFileFormats());
        on(settings).call("skipFilesFolders", json.getSkipFilesFolders());
        on(settings).call("tempDir", (String) null);
        on(settings).call("useIncrementalScan", json.isUseIncrementalScan());
        on(settings).call("useIssueTrackerIntegration", json.isUseIssueTrackerIntegration());

        // IBlackBoxSettings doesn't support some settings
        if (settings instanceof IBlackBoxSettings) return;
        // ICommonSettings doesn't support some settings
        if (settings instanceof ICommonSettings) return;

        on(settings).call("disableInterpretCores", false);
        on(settings).call("isDownloadDependencies", json.isDownloadDependencies());
        on(settings).call("isGraphEnabled", false);
        on(settings).call("isUnpackUserPackages", json.isUnpackUserPackages());
        on(settings).call("isUseEntryAnalysisPoint", json.isUseEntryAnalysisPoint());
        on(settings).call("isUsePublicAnalysisMethod", json.isUsePublicAnalysisMethod());
    }

    public Object getProgrammingLanguageV36(@NonNull final ScanSettings.ProgrammingLanguage language) {
        // Java, Php, Csharp, Vb, ObjectiveC, CPlusPlus, Sql, Swift, Python, JavaScript, Kotlin, Go
        if (JAVA.equals(language))
            return ProgrammingLanguage.Java;
        else if (ScanSettings.ProgrammingLanguage.PHP.equals(language))
            return ProgrammingLanguage.Php;
        else if (ScanSettings.ProgrammingLanguage.CSHARP.equals(language))
            return ProgrammingLanguage.CSharp;
        else if (ScanSettings.ProgrammingLanguage.VB.equals(language))
            return ProgrammingLanguage.VB;
        else if (ScanSettings.ProgrammingLanguage.SQL.equals(language))
            return ProgrammingLanguage.PlSql;
        else if (ScanSettings.ProgrammingLanguage.CPLUSPLUS.equals(language))
            return ProgrammingLanguage.CPlusPlus;
        else if (ScanSettings.ProgrammingLanguage.SWIFT.equals(language))
            return ProgrammingLanguage.Swift;
        else if (ScanSettings.ProgrammingLanguage.PYTHON.equals(language))
            return ProgrammingLanguage.Python;
        else if (ScanSettings.ProgrammingLanguage.JAVASCRIPT.equals(language))
            return ProgrammingLanguage.JavaScript;
        else if (ScanSettings.ProgrammingLanguage.KOTLIN.equals(language))
            return ProgrammingLanguage.Kotlin;
        else if (ScanSettings.ProgrammingLanguage.GO.equals(language))
            return ProgrammingLanguage.Go;
        else
            return ProgrammingLanguage.None;
    }

    protected BlackBoxAuthentication fillAuthentication(@NonNull final BlackBoxAuthentication auth, @NonNull final ScanSettings.Authentication jsonAuth) {
        ScanSettings.AuthItem jsonAuthItem = jsonAuth.getAuthItem();
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
            if (ScanSettings.CredentialsType.FORM.equals(jsonAuthItem.getCredentials().getType()))
                credentials.setType(AuthType.Form);
            else if (ScanSettings.CredentialsType.HTTP.equals(jsonAuthItem.getCredentials().getType()))
                credentials.setType(AuthType.Http);
            else if (ScanSettings.CredentialsType.NONE.equals(jsonAuthItem.getCredentials().getType()))
                credentials.setType(AuthType.None);
            else if (ScanSettings.CredentialsType.COOKIE.equals(jsonAuthItem.getCredentials().getType()))
                credentials.setType(AuthType.RawCookie);
            if (null != jsonAuthItem.getCredentials().getLogin()) {
                ScanSettings.Login jsonLogin = jsonAuthItem.getCredentials().getLogin();
                credentials.login(new MappedAuthenticationObject()
                        .name(jsonLogin.getName())
                        .value(jsonLogin.getValue())
                        .isRegexp(jsonLogin.isRegexpUsed())
                        .regexp(jsonLogin.getRegexp())
                );
            }
            if (null != jsonAuthItem.getCredentials().getPassword()) {
                ScanSettings.Password jsonPassword = jsonAuthItem.getCredentials().getPassword();
                credentials.password(new MappedAuthenticationObject()
                        .name(jsonPassword.getName())
                        .value(jsonPassword.getValue())
                        .isRegexp(jsonPassword.isRegexpUsed())
                        .regexp(jsonPassword.getRegexp())
                );
            }
        }

        auth.setAuthItem(authItem);
        return auth;
    }

    protected BlackBoxProxySettings fillProxy(@NonNull final BlackBoxProxySettings proxy, @NonNull final ScanSettings.ProxySettings jsonProxy) {
        proxy.host(jsonProxy.getHost())
                .port(jsonProxy.getPort())
                .username(jsonProxy.getUsername())
                .password(jsonProxy.getPassword())
                .isEnabled(jsonProxy.isEnabled());

        if (null != jsonProxy.getType()) {
            ScanSettings.ProxyType jsonType = jsonProxy.getType();
            if (ScanSettings.ProxyType.HTTP.equals(jsonType))
                proxy.setType(ProxyType.Http);
            else if (ScanSettings.ProxyType.HTTPNOCONNECT.equals(jsonType))
                proxy.setType(ProxyType.HttpNoConnect);
            else if (ScanSettings.ProxyType.SOCKS4.equals(jsonType))
                proxy.setType(ProxyType.Socks4);
            else if (ScanSettings.ProxyType.SOCKS5.equals(jsonType))
                proxy.setType(ProxyType.Socks5);
        }

        return proxy;
    }

    public void fillScanSettings(@NonNull final IScanSettings settings, @NonNull final ScanSettings json) {
        // Vulnerability search modules. Possible values are: Php, Java, CSharp, Configuration, Fingerprint (includes DependencyCheck), PmTaint , BlackBox, JavaScript
        List<String> scanAppType = Arrays.stream(json.getScanAppType().split("[, ]+"))
                .map(t -> t.trim()).collect(Collectors.toList());
        // Check if PHP / Java / C# modules are to be engaged
        if (scanAppType.stream().anyMatch(t -> "Php".equalsIgnoreCase(t))) {
            IPhpSettings languageSettings = new IPhpSettings().scanAppType(ScanAppType.PHP);
            fillCommonFields(languageSettings, json);
            settings.setPhp(languageSettings);
        }
        if (scanAppType.stream().anyMatch(t -> "Java".equalsIgnoreCase(t))) {
            IJavaSettings languageSettings = new IJavaSettings().scanAppType(ScanAppType.Java);
            fillCommonFields(languageSettings, json);
            languageSettings
                    .javaParameters(json.getJavaParameters())
                    .javaVersion(0 == json.getJavaVersion() ? JavaVersions.v1_8 : JavaVersions.v1_11);
            settings.setJava(languageSettings);
        }

        if (scanAppType.stream().anyMatch(t -> "CSharp".equalsIgnoreCase(t))) {
            ICSharpSettings languageSettings = new ICSharpSettings().scanAppType(ScanAppType.CSharp);
            fillCommonFields(languageSettings, json);
            languageSettings
                    .projectType("Solution".equalsIgnoreCase(json.getProjectType()) ? DotNetProjectType.Solution : DotNetProjectType.WebSite)
                    .solutionFile(json.getSolutionFile())
                    .webSiteFolder(json.getWebSiteFolder());
            settings.setDotNet(languageSettings);
        }

        if (scanAppType.stream().anyMatch(t -> ("Configuration".equalsIgnoreCase(t)))) {
            IConfigSettings languageSettings = new IConfigSettings().scanAppType(ScanAppType.Configuration);
            fillCommonFields(languageSettings, json);
            // TODO: Check ignored configurationFiles as there's now such setting in aiproj JSON
            settings.setConfiguration(languageSettings);
        }

        if (scanAppType.stream().anyMatch(t -> ("Fingerprint".equalsIgnoreCase(t)))) {
            IFingerprintSettings fingerprintSettings = new IFingerprintSettings().scanAppType(ScanAppType.Fingerprint);
            fillCommonFields(fingerprintSettings, json);
            fingerprintSettings
                    .useDefaultFingerprints(json.isUseDefaultFingerprints())
                    .useCustomYaraRules(json.isUseCustomYaraRules());
            // TODO: Check ignored customYaraRules as for v3.6 it can be setup only via viewer
            settings.setFingerprint(fingerprintSettings);

            IDependencyCheckSettings dependencyCheckSettings = new IDependencyCheckSettings().scanAppType(ScanAppType.DependencyCheck);
            fillCommonFields(dependencyCheckSettings, json);
            // TODO: Check ignored isDependencyCheckAutoUpdateEnabled as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateBaseUrl as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateModifiedUrl as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckDataBaseFolder as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateRetireJsUrl as there's now such setting in aiproj JSON
            settings.setDependencyCheck(dependencyCheckSettings);
        }

        if (scanAppType.stream().anyMatch(t -> ("PmTaint".equalsIgnoreCase(t)))) {
            IPmTaintSettings languageSettings = new IPmTaintSettings().scanAppType(ScanAppType.PmTaint);
            fillCommonFields(languageSettings, json);
            languageSettings
                    .usePmAnalysis(json.isUsePmAnalysis())
                    .useTaintAnalysis(json.isUseTaintAnalysis())
                    .disabledPatterns(json.getDisabledPatterns());
            // TODO: Check ignored enabledPatterns as there's now such setting in aiproj JSON
            settings.setPmTaint(languageSettings);
        }

        if (scanAppType.stream().anyMatch(t -> ("BlackBox".equalsIgnoreCase(t)))) {
            IBlackBoxSettings languageSettings = new IBlackBoxSettings().scanAppType(ScanAppType.BlackBox);
            languageSettings.level(BlackBoxScanLevel.valueOf(json.getBlackBoxScanLevel().toString()));
            // TODO: Check ignored scanScope as there's now such setting in aiproj JSON
            // TODO: Check ignored configurationPath as there's now such setting in aiproj JSON
            // TODO: Check ignored bindAddress as there's now such setting in aiproj JSON
            languageSettings.autocheckSite(json.getAutocheckSite());
            languageSettings.customHeaders(json.getCustomHeaders());
            languageSettings.autocheckCustomHeaders(json.getAutocheckCustomHeaders());

            ScanSettings.Authentication jsonAuth = json.getAuthentication();
            if (null != jsonAuth)
                languageSettings.authentication(fillAuthentication(new BlackBoxAuthentication(), jsonAuth));
            ScanSettings.ProxySettings jsonProxy = json.getProxySettings();
            if (null != jsonProxy)
                languageSettings.proxySettings(fillProxy(new BlackBoxProxySettings(), jsonProxy));

            jsonAuth = json.getAutocheckAuthentication();
            if (null != jsonAuth)
                languageSettings.autocheckAuthentication(fillAuthentication(new BlackBoxAuthentication(), jsonAuth));
            jsonProxy = json.getAutocheckProxySettings();
            if (null != jsonProxy)
                languageSettings.autocheckProxySettings(fillProxy(new BlackBoxProxySettings(), jsonProxy));

            settings.setBlackBox(languageSettings);
        }

        if (scanAppType.stream().anyMatch(t -> ("JavaScript".equalsIgnoreCase(t)))) {
            IJavaScriptSettings languageSettings = new IJavaScriptSettings().scanAppType(ScanAppType.JavaScript);
            fillCommonFields(languageSettings, json);
            languageSettings
                    .javaScriptProjectFile(json.getJavaScriptProjectFile())
                    .javaScriptProjectFolder(json.getJavaScriptProjectFolder());
            settings.setJavaScript(languageSettings);
        }
    }
}
