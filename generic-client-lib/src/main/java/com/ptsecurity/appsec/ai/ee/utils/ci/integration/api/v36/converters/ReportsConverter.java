package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.*;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.collections.CollectionUtils.isEmpty;
import static org.apache.commons.collections.CollectionUtils.isNotEmpty;

@Slf4j
public class ReportsConverter {
    private static final Map<Reports.IssuesFilter.Level, IssuesFilterLevel> REVERSE_ISSUE_FILTER_LEVEL_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.Condition, IssuesFilterExploitationCondition> REVERSE_ISSUE_FILTER_CONDITION_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.ScanMode, IssuesFilterScanMode> REVERSE_ISSUE_FILTER_SCANMODE_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.ActualStatus, IssuesFilterActualStatus> REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.ApprovalState, IssuesFilterConfirmationStatus> REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.SuppressStatus, IssuesFilterSuppressStatus> REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.SourceType, IssuesFilterSourceType> REVERSE_ISSUE_FILTER_SOURCETYPE_MAP = new HashMap<>();

    static {
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.NONE, IssuesFilterLevel.None);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.LOW, IssuesFilterLevel.Low);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.MEDIUM, IssuesFilterLevel.Medium);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.HIGH, IssuesFilterLevel.High);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.POTENTIAL, IssuesFilterLevel.Potential);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.ALL, IssuesFilterLevel.All);

        REVERSE_ISSUE_FILTER_CONDITION_MAP.put(Reports.IssuesFilter.Condition.NONE, IssuesFilterExploitationCondition.None);
        REVERSE_ISSUE_FILTER_CONDITION_MAP.put(Reports.IssuesFilter.Condition.NOCONDITION, IssuesFilterExploitationCondition.NoCondition);
        REVERSE_ISSUE_FILTER_CONDITION_MAP.put(Reports.IssuesFilter.Condition.UNDERCONDITION, IssuesFilterExploitationCondition.UnderCondition);
        REVERSE_ISSUE_FILTER_CONDITION_MAP.put(Reports.IssuesFilter.Condition.ALL, IssuesFilterExploitationCondition.All);

        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.NONE, IssuesFilterScanMode.None);
        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.FROMENTRYPOINT, IssuesFilterScanMode.FromEntryPoint);
        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.FROMPUBLICPROTECTED, IssuesFilterScanMode.FromPublicProtected);
        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.FROMOTHER, IssuesFilterScanMode.FromOther);
        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.ALL, IssuesFilterScanMode.All);

        REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP.put(Reports.IssuesFilter.ActualStatus.ISNEW, IssuesFilterActualStatus.ISNEW);
        REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP.put(Reports.IssuesFilter.ActualStatus.NOTISNEW, IssuesFilterActualStatus.NOTISNEW);
        REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP.put(Reports.IssuesFilter.ActualStatus.ALL, IssuesFilterActualStatus.ALL);

        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.UNDEFINED, IssuesFilterConfirmationStatus.Undefined);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.NONE, IssuesFilterConfirmationStatus.None);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.APPROVED, IssuesFilterConfirmationStatus.Approved);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.AUTOAPPROVED, IssuesFilterConfirmationStatus.AutoApproved);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.DISCARDED, IssuesFilterConfirmationStatus.Discarded);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.ALL, IssuesFilterConfirmationStatus.All);

        REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.put(Reports.IssuesFilter.SuppressStatus.NONE, IssuesFilterSuppressStatus.None);
        REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.put(Reports.IssuesFilter.SuppressStatus.SUPPRESSED, IssuesFilterSuppressStatus.Suppressed);
        REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.put(Reports.IssuesFilter.SuppressStatus.EXCEPTSUPPRESSED, IssuesFilterSuppressStatus.ExceptSuppressed);
        REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.put(Reports.IssuesFilter.SuppressStatus.ALL, IssuesFilterSuppressStatus.All);

        REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.put(Reports.IssuesFilter.SourceType.NONE, IssuesFilterSourceType.None);
        REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.put(Reports.IssuesFilter.SourceType.STATIC, IssuesFilterSourceType.Static);
        REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.put(Reports.IssuesFilter.SourceType.BLACKBOX, IssuesFilterSourceType.BlackBox);
        REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.put(Reports.IssuesFilter.SourceType.ALL, IssuesFilterSourceType.All);
    }

    @NonNull
    public static IssuesFilter convert(@NonNull final Reports.IssuesFilter filter) {
        IssuesFilter res = new IssuesFilter();
        // No filters are defined - set ALL value
        if (null == filter.getIssueLevel() && isEmpty(filter.getIssueLevels()))
            res.setIssueLevel(IssuesFilterLevel.All.getValue());
        else {
            int rawValue = 0;
            if (null != filter.getIssueLevel())
                rawValue = REVERSE_ISSUE_FILTER_LEVEL_MAP.get(filter.getIssueLevel()).getValue();
            if (isNotEmpty(filter.getIssueLevels())) {
                for (Reports.IssuesFilter.Level item : filter.getIssueLevels())
                    rawValue |= REVERSE_ISSUE_FILTER_LEVEL_MAP.get(item).getValue();
            }
            res.setIssueLevel(rawValue);
        }

        // No exploitation conditions are defined - set ALL value
        if (null == filter.getExploitationCondition() && isEmpty(filter.getExploitationConditions()))
            res.setExploitationCondition(IssuesFilterExploitationCondition.All.getValue());
        else {
            int rawValue = 0;
            if (null != filter.getExploitationCondition())
                rawValue = REVERSE_ISSUE_FILTER_CONDITION_MAP.get(filter.getExploitationCondition()).getValue();
            if (isNotEmpty(filter.getExploitationConditions())) {
                for (Reports.IssuesFilter.Condition item : filter.getExploitationConditions())
                    rawValue |= REVERSE_ISSUE_FILTER_CONDITION_MAP.get(item).getValue();
            }
            res.setExploitationCondition(rawValue);
        }

        // No scan modes are defined - set ALL value
        if (null == filter.getScanMode() && isEmpty(filter.getScanModes()))
            res.setScanMode(IssuesFilterScanMode.All.getValue());
        else {
            int rawValue = 0;
            if (null != filter.getScanMode())
                rawValue = REVERSE_ISSUE_FILTER_SCANMODE_MAP.get(filter.getScanMode()).getValue();
            if (isNotEmpty(filter.getScanModes())) {
                for (Reports.IssuesFilter.ScanMode item : filter.getScanModes())
                    rawValue |= REVERSE_ISSUE_FILTER_SCANMODE_MAP.get(item).getValue();
            }
            res.setScanMode(rawValue);
        }

        // No suppress statuses are defined - set ALL value
        if (null == filter.getSuppressStatus() && isEmpty(filter.getSuppressStatuses()))
            res.setSuppressStatus(IssuesFilterSuppressStatus.All.getValue());
        else {
            int rawValue = 0;
            if (null != filter.getSuppressStatus())
                rawValue = REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.get(filter.getSuppressStatus()).getValue();
            if (isNotEmpty(filter.getSuppressStatuses())) {
                for (Reports.IssuesFilter.SuppressStatus item : filter.getSuppressStatuses())
                    rawValue |= REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.get(item).getValue();
            }
            res.setSuppressStatus(rawValue);
        }

        // No confirmation statuses are defined - set ALL value
        if (null == filter.getConfirmationStatus() && isEmpty(filter.getConfirmationStatuses()))
            res.setConfirmationStatus(IssuesFilterConfirmationStatus.All.getValue());
        else {
            int rawValue = 0;
            if (null != filter.getConfirmationStatus())
                rawValue = REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.get(filter.getConfirmationStatus()).getValue();
            if (isNotEmpty(filter.getConfirmationStatuses())) {
                for (Reports.IssuesFilter.ApprovalState item : filter.getConfirmationStatuses())
                    rawValue |= REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.get(item).getValue();
            }
            res.setConfirmationStatus(rawValue);
        }

        // No source types are defined - set ALL value
        if (null == filter.getSourceType() && isEmpty(filter.getSourceTypes()))
            res.setSourceType(IssuesFilterSourceType.All.getValue());
        else {
            int rawValue = 0;
            if (null != filter.getSourceType())
                rawValue = REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.get(filter.getSourceType()).getValue();
            if (isNotEmpty(filter.getSourceTypes())) {
                for (Reports.IssuesFilter.SourceType item : filter.getSourceTypes())
                    rawValue |= REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.get(item).getValue();
            }
            res.setSourceType(rawValue);
        }

        res.setActualStatus(null == filter.getActualStatus()
                ? IssuesFilterActualStatus.ALL
                : REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP.get(filter.getActualStatus()));

        res.setHideSecondOrder(null != filter.getHideSecondOrder() && filter.getHideSecondOrder());
        res.setHideSuspected(null != filter.getHideSuspected() && filter.getHideSuspected());
        res.setHidePotential(null != filter.getHidePotential() && filter.getHidePotential());

        res.setByFavorite(null != filter.getByFavorite() && filter.getByFavorite());
        res.setByBestPlaceToFix(null != filter.getByBestPlaceToFix() && filter.getByBestPlaceToFix());

        res.setTypes(convert(filter.getTypes()));
        res.setPattern(filter.getPattern());

        res.setSelectAllLevelsSeparately(null != filter.getSelectAllLevelsSeparately() && filter.getSelectAllLevelsSeparately());
        res.setSelectAllConfirmationStatusSeparately(null != filter.getSelectAllConfirmationStatusSeparately() && filter.getSelectAllConfirmationStatusSeparately());
        res.setSelectAllExploitationConditionSeparately(null != filter.getSelectAllExploitationConditionSeparately() && filter.getSelectAllExploitationConditionSeparately());
        res.setSelectAllSuppressStatusSeparately(null != filter.getSelectAllSuppressStatusSeparately() && filter.getSelectAllSuppressStatusSeparately());
        res.setSelectAllScanModeSeparately(null != filter.getSelectAllScanModeSeparately() && filter.getSelectAllScanModeSeparately());
        res.setSelectAllActualStatusSeparately(null != filter.getSelectAllActualStatusSeparately() && filter.getSelectAllActualStatusSeparately());

        return res;
    }

    @NonNull
    public static List<IssuesFilterType> convert(@NonNull final List<String> types) {
        List<IssuesFilterType> res = new ArrayList<>();
        for (String type : types)
            res.add(new IssuesFilterType().value(type).enable(true));
        return res;
    }
}
