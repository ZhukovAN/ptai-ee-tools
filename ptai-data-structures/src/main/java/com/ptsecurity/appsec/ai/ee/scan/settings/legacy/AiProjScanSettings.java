package com.ptsecurity.appsec.ai.ee.scan.settings.legacy;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AiprojLegacy;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings.ScanAppType.DEPENDENCYCHECK;
import static com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings.ScanAppType.FINGERPRINT;

@Slf4j
public class AiProjScanSettings extends AiprojLegacy implements UnifiedAiProjScanSettings {
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
    }

    @Override
    public Set<ScanModule> getScanModules() {
        Set<ScanModule> res = new HashSet<>();
        Set<ScanAppType> scanAppTypes = Arrays.stream(scanAppType.split("[, ]+"))
                .map(ScanAppType::from)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        // "Vulnerable source code" checkbox means that we either enabled AI-supported PHP / Java / C# / JS scan mode ...
        if (scanAppTypes.stream().anyMatch(SCAN_APP_TYPE_AI::contains)) res.add(ScanModule.VULNERABLESOURCECODE);
        

        boolean checkScanAppTypeResult = scanAppTypes.stream().anyMatch(SCAN_APP_TYPE_AI::contains);
        // ... or all other languages with PmTaint / UseTaintAnalysis enabled
        boolean checkTaintOnlyLanguage = !LANGUAGE_AI.contains(settings.getProgrammingLanguage()) &&
                scanAppTypes.contains(AiProjScanSettings.ScanAppType.PMTAINT) &&
                null != settings.getUseTaintAnalysis() && settings.getUseTaintAnalysis();
        model.setSearchForVulnerableSourceCodeEnabled(checkScanAppTypeResult || checkTaintOnlyLanguage);
        model.setDataFlowAnalysisEnabled(null != settings.getUseTaintAnalysis() && settings.getUseTaintAnalysis() && scanAppTypes.contains(AiProjScanSettings.ScanAppType.PMTAINT));
        model.setPatternMatchingEnabled(null != settings.getUsePmAnalysis() && settings.getUsePmAnalysis() && scanAppTypes.contains(AiProjScanSettings.ScanAppType.PMTAINT));
        model.setSearchForConfigurationFlawsEnabled(scanAppTypes.contains(AiProjScanSettings.ScanAppType.CONFIGURATION));
        model.setSearchForVulnerableComponentsEnabled(scanAppTypes.contains(FINGERPRINT) || scanAppTypes.contains(DEPENDENCYCHECK));



        if ()
        return null;
    }

    @Override
    public ScanBrief.ScanSettings.@NonNull Language getProgrammingLanguage() {
        return PROGRAMMING_LANGUAGE_MAP.get(programmingLanguage);
    }
}
