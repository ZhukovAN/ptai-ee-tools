package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.NonNull;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings.ProgrammingLanguage.JAVA;

/**
 * As v.3.6 REST API definition contain errors, we need utility to fill manually
 * added V36ScanSettings instance with values from parsed aiproj JSON file. And as
 * V36ScanSettings is literally an interface multiply inherited from IPhpSettings,
 * IConfigurationSettings etc., we may use ScanSettingsHelper's reflection-based
 * methods to fill V36ScanSettings fields
 */
public class V36ScanSettingsHelper extends ScanSettingsHelper {

    @Override
    public Object getProgrammingLanguageV36(@NonNull final ScanSettings.ProgrammingLanguage language) {
        // Java, Php, Csharp, Vb, ObjectiveC, CPlusPlus, Sql, Swift, Python, JavaScript, Kotlin, Go
        if (JAVA.equals(language))
            return V36ProgrammingLanguage.JAVA;
        else if (ScanSettings.ProgrammingLanguage.PHP.equals(language))
            return V36ProgrammingLanguage.PHP;
        else if (ScanSettings.ProgrammingLanguage.CSHARP.equals(language))
            return V36ProgrammingLanguage.CSHARP;
        else if (ScanSettings.ProgrammingLanguage.VB.equals(language))
            return V36ProgrammingLanguage.VB;
        else if (ScanSettings.ProgrammingLanguage.SQL.equals(language))
            return V36ProgrammingLanguage.PLSQL;
        else if (ScanSettings.ProgrammingLanguage.CPLUSPLUS.equals(language))
            return V36ProgrammingLanguage.CPLUSPLUS;
        else if (ScanSettings.ProgrammingLanguage.SWIFT.equals(language))
            return V36ProgrammingLanguage.SWIFT;
        else if (ScanSettings.ProgrammingLanguage.PYTHON.equals(language))
            return V36ProgrammingLanguage.PYTHON;
        else if (ScanSettings.ProgrammingLanguage.JAVASCRIPT.equals(language))
            return V36ProgrammingLanguage.JAVASCRIPT;
        else if (ScanSettings.ProgrammingLanguage.KOTLIN.equals(language))
            return V36ProgrammingLanguage.KOTLIN;
        else if (ScanSettings.ProgrammingLanguage.GO.equals(language))
            return V36ProgrammingLanguage.GO;
        else
            return V36ProgrammingLanguage.NONE;
    }

    public void fillV36ScanSettings(@NonNull final V36ScanSettings settings, @NonNull final ScanSettings json) {
        // Vulnerability search modules. Possible values are: Php, Java, CSharp, Configuration, Fingerprint (includes DependencyCheck), PmTaint , BlackBox, JavaScript
        List<String> scanAppType = Arrays.stream(json.getScanAppType().split("[, ]+"))
                .map(t -> t.trim()).collect(Collectors.toList());
        //
        settings.setScanAppType(json.getScanAppType());
        // Check if PHP / Java / C# modules are to be engaged
        if (scanAppType.stream().anyMatch(t -> ScanSettings.ScanAppType.Php.name().equalsIgnoreCase(t))) {
            fillCommonFields(settings, json);
        }
        if (scanAppType.stream().anyMatch(t -> ScanSettings.ScanAppType.Java.name().equalsIgnoreCase(t))) {
            fillCommonFields(settings, json);
            settings
                    .javaParameters(json.getJavaParameters())
                    .javaVersion(0 == json.getJavaVersion() ? JavaVersions.v1_8 : JavaVersions.v1_11)
                    .useJavaNormalizeVersionPattern(json.isUseJavaNormalizeVersionPattern())
                    .javaNormalizeVersionPattern(json.getJavaNormalizeVersionPattern());
        }

        if (scanAppType.stream().anyMatch(t -> ScanSettings.ScanAppType.CSharp.name().equalsIgnoreCase(t))) {
            fillCommonFields(settings, json);
            settings
                    .projectType("Solution".equalsIgnoreCase(json.getProjectType()) ? DotNetProjectType.Solution : DotNetProjectType.WebSite)
                    .solutionFile(json.getSolutionFile())
                    .webSiteFolder(json.getWebSiteFolder());
        }

        if (scanAppType.stream().anyMatch(t -> (ScanSettings.ScanAppType.Configuration.name().equalsIgnoreCase(t)))) {
            fillCommonFields(settings, json);
            // TODO: Check ignored configurationFiles as there's now such setting in aiproj JSON
        }

        if (scanAppType.stream().anyMatch(t -> (ScanSettings.ScanAppType.Fingerprint.name().equalsIgnoreCase(t)))) {
            fillCommonFields(settings, json);
            settings
                    .useDefaultFingerprints(json.isUseDefaultFingerprints())
                    .useCustomYaraRules(json.isUseCustomYaraRules());
            // TODO: Check ignored customYaraRules as for v3.6 it can be setup only via viewer

            // TODO: Check ignored isDependencyCheckAutoUpdateEnabled as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateBaseUrl as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateModifiedUrl as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckDataBaseFolder as there's now such setting in aiproj JSON
            // TODO: Check ignored dependencyCheckAutoUpdateRetireJsUrl as there's now such setting in aiproj JSON
        }

        if (scanAppType.stream().anyMatch(t -> (ScanSettings.ScanAppType.PmTaint.name().equalsIgnoreCase(t)))) {
            fillCommonFields(settings, json);
            settings
                    .usePmAnalysis(json.isUsePmAnalysis())
                    .useTaintAnalysis(json.isUseTaintAnalysis())
                    .disabledPatterns(json.getDisabledPatterns());
            // TODO: Check ignored enabledPatterns as there's now such setting in aiproj JSON
        }

        if (scanAppType.stream().anyMatch(t -> (ScanSettings.ScanAppType.BlackBox.name().equalsIgnoreCase(t)))) {
            settings
                    .level(BlackBoxScanLevel.valueOf(json.getBlackBoxScanLevel().toString()))
                    .autocheckSite(json.getAutocheckSite())
                    .customHeaders(json.getCustomHeaders())
                    .autocheckCustomHeaders(json.getAutocheckCustomHeaders());
            // TODO: Check ignored scanScope as there's now such setting in aiproj JSON
            // TODO: Check ignored configurationPath as there's now such setting in aiproj JSON
            // TODO: Check ignored bindAddress as there's now such setting in aiproj JSON

            ScanSettings.Authentication jsonAuth = json.getAuthentication();
            if (null != jsonAuth)
                settings.authentication(fillAuthentication(new BlackBoxAuthentication(), jsonAuth));
            ScanSettings.ProxySettings jsonProxy = json.getProxySettings();
            if (null != jsonProxy)
                settings.proxySettings(fillProxy(new BlackBoxProxySettings(), jsonProxy));

            jsonAuth = json.getAutocheckAuthentication();
            if (null != jsonAuth)
                settings.autocheckAuthentication(fillAuthentication(new BlackBoxAuthentication(), jsonAuth));
            jsonProxy = json.getAutocheckProxySettings();
            if (null != jsonProxy)
                settings.autocheckProxySettings(fillProxy(new BlackBoxProxySettings(), jsonProxy));
        }

        if (scanAppType.stream().anyMatch(t -> (ScanSettings.ScanAppType.JavaScript.name().equalsIgnoreCase(t)))) {
            fillCommonFields(settings, json);
            settings
                    .javaScriptProjectFile(json.getJavaScriptProjectFile())
                    .javaScriptProjectFolder(json.getJavaScriptProjectFolder());
        }
    }
}
