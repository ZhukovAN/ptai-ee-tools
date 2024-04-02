package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v470.converters;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.server.v470.api.model.ProgrammingLanguageLicence;
import com.ptsecurity.appsec.ai.ee.server.v470.api.model.ScanModuleType;
import com.ptsecurity.appsec.ai.ee.server.v470.api.model.UserReportFiltersModel;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.server.v470.api.model.ScanModuleType.*;

@Slf4j
public class ReportsConverter {

    public static UserReportFiltersModel convert(Reports.IssuesFilter uniqModel) {

        UserReportFiltersModel apiModel = createDefaultFilters();
        applyLevelFilters(apiModel, uniqModel);
        applyLanguageFilters(apiModel, uniqModel);
        applyScanModules(apiModel, uniqModel);
        applyStatusFilters(apiModel, uniqModel);
        applySuppressFilters(apiModel, uniqModel);
        applyScanModeFilters(apiModel, uniqModel);
        applyConditionalFilters(apiModel, uniqModel);
        applyOtherFilters(apiModel, uniqModel);

        return apiModel;
    }

    private static void applyOtherFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Boolean byBestPlace = uniqModel.getByBestPlaceToFix();
        Boolean byFavorite = uniqModel.getByFavorite();
        Boolean secondLevel = uniqModel.getHideSecondOrder();
        Boolean suspected = uniqModel.getHideSuspected();
        if (byBestPlace != null) {
            apiModel.setNoPlaceToFix(byBestPlace);
        }
        if (byFavorite != null) {
            apiModel.setOnlyFavorite(byFavorite);
        }
        if (secondLevel != null) {
            apiModel.setSecondLevel(secondLevel);
        }
        if (suspected != null) {
            apiModel.setSuspected(suspected);
        }
    }

    private static void applyConditionalFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Reports.IssuesFilter.Condition exploitationCondition = uniqModel.getExploitationCondition();
        if (exploitationCondition != null) {
            apiModel.setConditional(exploitationCondition.equals(Reports.IssuesFilter.Condition.UNDERCONDITION) || exploitationCondition.equals(Reports.IssuesFilter.Condition.ALL));
            apiModel.setNonConditional(exploitationCondition.equals(Reports.IssuesFilter.Condition.NOCONDITION) || exploitationCondition.equals(Reports.IssuesFilter.Condition.ALL));
            return;
        }

        List<Reports.IssuesFilter.Condition> exploitationConditions = uniqModel.getExploitationConditions();
        if (exploitationConditions == null) {
            return;
        }
        apiModel.setConditional(exploitationConditions.contains(Reports.IssuesFilter.Condition.UNDERCONDITION) || exploitationConditions.contains(Reports.IssuesFilter.Condition.ALL));
        apiModel.setNonConditional(exploitationConditions.contains(Reports.IssuesFilter.Condition.NOCONDITION) || exploitationConditions.contains(Reports.IssuesFilter.Condition.ALL));
    }

    private static void applyScanModeFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Reports.IssuesFilter.ScanMode scanMode = uniqModel.getScanMode();
        if (scanMode != null) {
            apiModel.setModeEntryPoint(scanMode.equals(Reports.IssuesFilter.ScanMode.FROMENTRYPOINT) || scanMode.equals(Reports.IssuesFilter.ScanMode.ALL));
            apiModel.setModePublicMethods(scanMode.equals(Reports.IssuesFilter.ScanMode.FROMPUBLICPROTECTED) || scanMode.equals(Reports.IssuesFilter.ScanMode.ALL));
            apiModel.setModeOthers(scanMode.equals(Reports.IssuesFilter.ScanMode.FROMOTHER) || scanMode.equals(Reports.IssuesFilter.ScanMode.ALL));
            apiModel.setModeRootFunction(scanMode.equals(Reports.IssuesFilter.ScanMode.FROMROOT) || scanMode.equals(Reports.IssuesFilter.ScanMode.ALL));
            return;
        }

        List<Reports.IssuesFilter.ScanMode> scanModes = uniqModel.getScanModes();
        if (scanModes == null) {
            return;
        }
        apiModel.setModeEntryPoint(scanModes.contains(Reports.IssuesFilter.ScanMode.FROMENTRYPOINT) || scanModes.contains(Reports.IssuesFilter.ScanMode.ALL));
        apiModel.setModePublicMethods(scanModes.contains(Reports.IssuesFilter.ScanMode.FROMPUBLICPROTECTED) || scanModes.contains(Reports.IssuesFilter.ScanMode.ALL));
        apiModel.setModeOthers(scanModes.contains(Reports.IssuesFilter.ScanMode.FROMOTHER) || scanModes.contains(Reports.IssuesFilter.ScanMode.ALL));
        apiModel.setModeRootFunction(scanModes.contains(Reports.IssuesFilter.ScanMode.FROMROOT) || scanModes.contains(Reports.IssuesFilter.ScanMode.ALL));
    }

    private static void applySuppressFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Reports.IssuesFilter.SuppressStatus suppressStatus = uniqModel.getSuppressStatus();
        if (suppressStatus != null) {
            apiModel.setSuppressed(suppressStatus.equals(Reports.IssuesFilter.SuppressStatus.SUPPRESSED) || suppressStatus.equals(Reports.IssuesFilter.SuppressStatus.ALL));
            apiModel.setNonSuppressed(suppressStatus.equals(Reports.IssuesFilter.SuppressStatus.EXCEPTSUPPRESSED) || suppressStatus.equals(Reports.IssuesFilter.SuppressStatus.ALL));
            return;
        }

        List<Reports.IssuesFilter.SuppressStatus> suppressStatuses = uniqModel.getSuppressStatuses();
        if (suppressStatuses == null) {
            return;
        }
        apiModel.setSuppressed(suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.SUPPRESSED) || suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.ALL));
        apiModel.setNonSuppressed(suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.EXCEPTSUPPRESSED) || suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.ALL));
    }

    private static void applyLevelFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Reports.IssuesFilter.Level issueLevel = uniqModel.getIssueLevel();
        if (issueLevel != null) {
            apiModel.setLevelHigh(issueLevel.equals(Reports.IssuesFilter.Level.HIGH) || issueLevel.equals(Reports.IssuesFilter.Level.ALL));
            apiModel.setLevelMedium(issueLevel.equals(Reports.IssuesFilter.Level.MEDIUM) || issueLevel.equals(Reports.IssuesFilter.Level.ALL));
            apiModel.setLevelLow(issueLevel.equals(Reports.IssuesFilter.Level.LOW) || issueLevel.equals(Reports.IssuesFilter.Level.ALL));
            apiModel.setLevelPotential(issueLevel.equals(Reports.IssuesFilter.Level.POTENTIAL) || issueLevel.equals(Reports.IssuesFilter.Level.ALL));
            return;
        }

        List<Reports.IssuesFilter.Level> issueLevels = uniqModel.getIssueLevels();
        if (issueLevels == null) {
            return;
        }
        apiModel.setLevelHigh(issueLevels.contains(Reports.IssuesFilter.Level.HIGH) || issueLevels.contains(Reports.IssuesFilter.Level.ALL));
        apiModel.setLevelMedium(issueLevels.contains(Reports.IssuesFilter.Level.MEDIUM) || issueLevels.contains(Reports.IssuesFilter.Level.ALL));
        apiModel.setLevelLow(issueLevels.contains(Reports.IssuesFilter.Level.LOW) || issueLevels.contains(Reports.IssuesFilter.Level.ALL));
        apiModel.setLevelPotential(issueLevels.contains(Reports.IssuesFilter.Level.POTENTIAL) || issueLevels.contains(Reports.IssuesFilter.Level.ALL));
    }

    private static void applyLanguageFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        List<ProgrammingLanguageLicence> allLanguages = Arrays.asList(ProgrammingLanguageLicence.JAVA, ProgrammingLanguageLicence.CSHARP, ProgrammingLanguageLicence.VB, ProgrammingLanguageLicence.PHP, ProgrammingLanguageLicence.JAVASCRIPT, ProgrammingLanguageLicence.PYTHON, ProgrammingLanguageLicence.OBJECTIVEC, ProgrammingLanguageLicence.SWIFT, ProgrammingLanguageLicence.CANDCPLUSPLUS, ProgrammingLanguageLicence.GO, ProgrammingLanguageLicence.KOTLIN, ProgrammingLanguageLicence.SQL, ProgrammingLanguageLicence.RUBY);

        Reports.IssuesFilter.ProgrammingLanguage language = uniqModel.getLanguage();
        if (language != null) {
            switch (language) {
                case ALL: apiModel.setLanguages(allLanguages);
                case JAVA: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.JAVA));
                case CSHARP: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.CSHARP));
                case VB: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.VB));
                case PHP: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.PHP));
                case JAVASCRIPT: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.JAVASCRIPT));
                case PYTHON: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.PYTHON));
                case OBJECTIVEC: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.OBJECTIVEC));
                case SWIFT: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.SWIFT));
                case CANDCPLUSPLUS: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.CANDCPLUSPLUS));
                case GO: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.GO));
                case KOTLIN: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.KOTLIN));
                case SQL: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.SQL));
                case RUBY: apiModel.setLanguages(Collections.singletonList(ProgrammingLanguageLicence.RUBY));
            }
            log.info("Language setted: {}", apiModel.getLanguages());
            return;
        }

        List<Reports.IssuesFilter.ProgrammingLanguage> languages = uniqModel.getLanguages();
        if (languages == null) {
            return;
        }
        List<ProgrammingLanguageLicence> mappedLanguages = new ArrayList<>();
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.ALL)) {
            apiModel.setLanguages(allLanguages);
            return;
        }

        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.JAVA)) {
            mappedLanguages.add(ProgrammingLanguageLicence.JAVA);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.CSHARP)) {
            mappedLanguages.add(ProgrammingLanguageLicence.CSHARP);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.VB)) {
            mappedLanguages.add(ProgrammingLanguageLicence.VB);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.PHP)) {
            mappedLanguages.add(ProgrammingLanguageLicence.PHP);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.JAVASCRIPT)) {
            mappedLanguages.add(ProgrammingLanguageLicence.JAVASCRIPT);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.PYTHON)) {
            mappedLanguages.add(ProgrammingLanguageLicence.PYTHON);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.OBJECTIVEC)) {
            mappedLanguages.add(ProgrammingLanguageLicence.OBJECTIVEC);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.SWIFT)) {
            mappedLanguages.add(ProgrammingLanguageLicence.SWIFT);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.CANDCPLUSPLUS)) {
            mappedLanguages.add(ProgrammingLanguageLicence.CANDCPLUSPLUS);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.GO)) {
            mappedLanguages.add(ProgrammingLanguageLicence.GO);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.KOTLIN)) {
            mappedLanguages.add(ProgrammingLanguageLicence.KOTLIN);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.SQL)) {
            mappedLanguages.add(ProgrammingLanguageLicence.SQL);
        }
        if (languages.contains(Reports.IssuesFilter.ProgrammingLanguage.RUBY)) {
            mappedLanguages.add(ProgrammingLanguageLicence.RUBY);
        }

        apiModel.setLanguages(mappedLanguages);
        log.info("Language setted 2: {}", apiModel.getLanguages());
    }

    private static void applyScanModules(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        HashSet<ScanModuleType> scanModules = new HashSet<>();

        Reports.IssuesFilter.SourceType scanModule = uniqModel.getSourceType();
        if (scanModule != null) {
            if (scanModule.equals(Reports.IssuesFilter.SourceType.ALL)) {
                scanModules.addAll(Arrays.asList(STATICCODEANALYSIS, BLACKBOX, CONFIGURATION, COMPONENTS, PATTERNMATCHING));
            }
            if (scanModule.equals(Reports.IssuesFilter.SourceType.STATIC)) {
                scanModules.addAll(Arrays.asList(STATICCODEANALYSIS, CONFIGURATION, COMPONENTS, PATTERNMATCHING));
            }
            if (scanModule.equals(Reports.IssuesFilter.SourceType.BLACKBOX)) {
                scanModules.add(BLACKBOX);
            }

            apiModel.setScanModules(new ArrayList<>(scanModules));
            return;
        }

        List<Reports.IssuesFilter.SourceType> sourceTypes = uniqModel.getSourceTypes();
        if (sourceTypes == null) {
            return;
        }
        if (sourceTypes.contains(Reports.IssuesFilter.SourceType.ALL)) {
            scanModules.addAll(Arrays.asList(STATICCODEANALYSIS, BLACKBOX, CONFIGURATION, COMPONENTS, PATTERNMATCHING));
        }
        if (sourceTypes.contains(Reports.IssuesFilter.SourceType.STATIC)) {
            scanModules.addAll(Arrays.asList(STATICCODEANALYSIS, CONFIGURATION, COMPONENTS, PATTERNMATCHING));
        }
        if (sourceTypes.contains(Reports.IssuesFilter.SourceType.BLACKBOX)) {
            scanModules.add(BLACKBOX);
        }

        apiModel.setScanModules(new ArrayList<>(scanModules));
    }

    private static void applyStatusFilters(UserReportFiltersModel apiModel, Reports.IssuesFilter uniqModel) {
        Reports.IssuesFilter.ApprovalState confirmationStatus = uniqModel.getConfirmationStatus();
        if (confirmationStatus != null) {
            apiModel.setStatusConfirmed(confirmationStatus.equals(Reports.IssuesFilter.ApprovalState.APPROVED) || confirmationStatus.equals(Reports.IssuesFilter.ApprovalState.ALL));
            apiModel.setStatusConfirmedAuto(confirmationStatus.equals(Reports.IssuesFilter.ApprovalState.AUTOAPPROVED) || confirmationStatus.equals(Reports.IssuesFilter.ApprovalState.ALL));
            apiModel.setStatusRejected(confirmationStatus.equals(Reports.IssuesFilter.ApprovalState.DISCARDED) || confirmationStatus.equals(Reports.IssuesFilter.ApprovalState.ALL));
            apiModel.setStatusUndefined(confirmationStatus.equals(Reports.IssuesFilter.ApprovalState.NONE) || confirmationStatus.equals(Reports.IssuesFilter.ApprovalState.ALL));
            return;
        }

        List<Reports.IssuesFilter.ApprovalState> confirmationStatuses = uniqModel.getConfirmationStatuses();
        if (confirmationStatuses == null) {
            return;
        }
        apiModel.setStatusConfirmed(confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.APPROVED) || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.ALL));
        apiModel.setStatusConfirmedAuto(confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.AUTOAPPROVED) || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.ALL));
        apiModel.setStatusRejected(confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.DISCARDED) || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.ALL));
        apiModel.setStatusUndefined(confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.NONE) || confirmationStatuses.contains(Reports.IssuesFilter.ApprovalState.ALL));
    }

    private static UserReportFiltersModel createDefaultFilters() {
        UserReportFiltersModel defaultFilters = new UserReportFiltersModel();

        defaultFilters.setLevelHigh(true);
        defaultFilters.setLevelMedium(true);
        defaultFilters.setLevelLow(true);
        defaultFilters.setLevelPotential(true);

        defaultFilters.setScanModules(Arrays.asList(STATICCODEANALYSIS, BLACKBOX, PATTERNMATCHING, COMPONENTS, CONFIGURATION));
        defaultFilters.setLanguages(new ArrayList<>());

        defaultFilters.setStatusConfirmed(true);
        defaultFilters.setStatusConfirmedAuto(true);
        defaultFilters.setStatusUndefined(true);
        defaultFilters.setStatusRejected(false);

        defaultFilters.setSuppressed(false);
        defaultFilters.setNonSuppressed(true);

        defaultFilters.conditional(true);
        defaultFilters.nonConditional(true);
        defaultFilters.foundPrevScan(true);
        defaultFilters.foundThisScan(true);
        defaultFilters.noPlaceToFix(true);
        defaultFilters.onlyFavorite(false);
        defaultFilters.secondLevel(true);
        defaultFilters.setSuspected(true);

        defaultFilters.setModeEntryPoint(true);
        defaultFilters.setModeOthers(true);
        defaultFilters.setModePublicMethods(true);
        defaultFilters.setModeRootFunction(true);

        return defaultFilters;
    }
}
