package com.ptsecurity.appsec.ai.ee.scan.settings.legacy;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.BlackBoxSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AiprojLegacy;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_11;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.JavaSettings.JavaVersion.v1_8;
import static java.lang.Boolean.TRUE;

@Slf4j
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

    private static final Map<AiprojLegacy.ProgrammingLanguage, ScanBrief.ScanSettings.Language> PROGRAMMING_LANGUAGE_MAP = new HashMap<>();
    private static final Map<AiprojLegacy.ProjectType, UnifiedAiProjScanSettings.DotNetSettings.ProjectType> DOTNET_PROJECT_TYPE_MAP = new HashMap<>();
    private static final Map<Integer, BlackBoxSettings.ProxySettings.Type> PROXY_TYPE_MAP = new HashMap<>();

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

        DOTNET_PROJECT_TYPE_MAP.put(ProjectType.NONE, DotNetSettings.ProjectType.NONE);
        DOTNET_PROJECT_TYPE_MAP.put(ProjectType.SOLUTION, DotNetSettings.ProjectType.SOLUTION);
        DOTNET_PROJECT_TYPE_MAP.put(ProjectType.WEB_SITE, DotNetSettings.ProjectType.WEBSITE);

        PROXY_TYPE_MAP.put(0, BlackBoxSettings.ProxySettings.Type.HTTP);
        PROXY_TYPE_MAP.put(1, BlackBoxSettings.ProxySettings.Type.HTTPNOCONNECT);
        PROXY_TYPE_MAP.put(2, BlackBoxSettings.ProxySettings.Type.SOCKS4);
        PROXY_TYPE_MAP.put(3, BlackBoxSettings.ProxySettings.Type.SOCKS5);
    }

    @Override
    public Set<ScanModule> getScanModules() {
        Set<ScanModule> res = new HashSet<>();
        Set<ScanAppType> scanAppTypes = Arrays.stream(scanAppType.split("[, ]+"))
                .map(ScanAppType::from)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        // See internal wiki pageId=193599549
        // "Vulnerable source code" checkbox means that we either enabled AI-supported PHP / Java / C# / JS scan mode ...
        boolean abstractIntrepretationCoreUsed = scanAppTypes.stream().anyMatch(SCAN_APP_TYPE_AI::contains);
        // ... or all other languages with PmTaint / UseTaintAnalysis enabled
        boolean taintOnlyLanguageUsed = !LANGUAGE_AI.contains(getProgrammingLanguage())
                && scanAppTypes.contains(ScanAppType.PMTAINT)
                && TRUE.equals(useTaintAnalysis);
        if (abstractIntrepretationCoreUsed || taintOnlyLanguageUsed) res.add(ScanModule.VULNERABLESOURCECODE);
        if (TRUE.equals(useTaintAnalysis) && scanAppTypes.contains(ScanAppType.PMTAINT)) res.add(ScanModule.DATAFLOWANALYSIS);
        if (TRUE.equals(usePmAnalysis) && scanAppTypes.contains(ScanAppType.PMTAINT)) res.add(ScanModule.PATTERNMATCHING);
        if (scanAppTypes.contains(ScanAppType.CONFIGURATION)) res.add(ScanModule.CONFIGURATION);
        if (scanAppTypes.contains(ScanAppType.BLACKBOX)) res.add(ScanModule.BLACKBOX);
        if (scanAppTypes.contains(ScanAppType.DEPENDENCYCHECK) || scanAppTypes.contains(ScanAppType.FINGERPRINT)) res.add(ScanModule.COMPONENTS);
        return res;
    }

    @Override
    public BlackBoxSettings getBlackBoxSettings() {
        if (!getScanModules().contains(ScanModule.BLACKBOX)) return null;

        BlackBoxSettings blackBoxSettings = new BlackBoxSettings();
        if (null != this.proxySettings)
            blackBoxSettings.setProxySettings(BlackBoxSettings.ProxySettings.builder()
                    .enabled(TRUE.equals(proxySettings.isEnabled))
                    .type(PROXY_TYPE_MAP.get(proxySettings.type))
                    .host(proxySettings.host)
                    .port(proxySettings.port)
                    .login(proxySettings.username)
                    .password(proxySettings.password)
                    .build());
        if (null != customHeaders) {
            blackBoxSettings.setAdditionalHttpHeaders(new ArrayList<>());
            for (List<String> header : customHeaders) {
                List<String> nonEmptyHeaders = header.stream().filter(StringUtils::isNotEmpty).collect(Collectors.toList());
                if (CollectionUtils.isEmpty(nonEmptyHeaders)) {
                    log.trace("Skip empty header");
                    continue;
                }

                if (2 > nonEmptyHeaders.size()) {
                    log.trace("Skip {} header as there's no value defined", nonEmptyHeaders.);
                }


            }
        }
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
                .solutionFile(solutionFile)
                .projectType(DOTNET_PROJECT_TYPE_MAP.getOrDefault(projectType, DotNetSettings.ProjectType.NONE))
                .build();
    }

    @Override
    public JavaSettings getJavaSettings() {
        return JavaSettings.builder()
                .parameters(javaParameters)
                .unpackUserPackages(TRUE.equals(isUnpackUserPackages))
                .javaVersion(AiprojLegacy.JavaVersion._0.equals(javaVersion) ? v1_8 : v1_11)
                .build();
    }

    @Override
    public @NonNull Boolean isSkipGitIgnoreFiles() {
        if (CollectionUtils.isEmpty(skipFilesFolders)) return false;
        return skipFilesFolders.contains(".gitignore");
    }

    @Override
    public @NonNull Boolean isUseSastRules() {
        throw GenericException.raise("No custom SAST rules support for legacy AIPROJ schema", new UnsupportedOperationException());
    }

    @Override
    public @NonNull Boolean isUseCustomPmRules() {
        throw GenericException.raise("No custom PM rules support for legacy AIPROJ schema", new UnsupportedOperationException());
    }

    @Override
    public @NonNull Boolean isUseCustomYaraRules() {
        return TRUE.equals(useCustomYaraRules);
    }

    @Override
    public @NonNull Boolean isUseSecurityPolicies() {
        throw GenericException.raise("No security policy support for legacy AIPROJ schema", new UnsupportedOperationException());
    }

    @Override
    public MailingProjectSettings getMailingProjectSettings() {
        throw GenericException.raise("No mail settings support for legacy AIPROJ schema", new UnsupportedOperationException());
    }

    @Override
    public void load(@NonNull String data) throws GenericException {

    }

    @Override
    public Version getVersion() {
        return Version.LEGACY;
    }
}
