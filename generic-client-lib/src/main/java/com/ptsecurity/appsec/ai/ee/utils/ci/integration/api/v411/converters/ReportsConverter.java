package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v411.converters;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.server.v411.legacy.model.*;
import com.ptsecurity.appsec.ai.ee.server.v411.projectmanagement.model.ReportFormatType;
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
    private static final Map<Reports.IssuesFilter.Level, V411IssuesFilterLevel> REVERSE_ISSUE_FILTER_LEVEL_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.Condition, V411IssuesFilterExploitationCondition> REVERSE_ISSUE_FILTER_CONDITION_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.ScanMode, V411IssuesFilterScanMode> REVERSE_ISSUE_FILTER_SCANMODE_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.ActualStatus, V411IssuesFilterActualStatus> REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.ApprovalState, V411IssuesFilterConfirmationStatus> REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.SuppressStatus, V411IssuesFilterSuppressStatus> REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP = new HashMap<>();
    private static final Map<Reports.IssuesFilter.SourceType, V411IssuesFilterSourceType> REVERSE_ISSUE_FILTER_SOURCETYPE_MAP = new HashMap<>();

    static {
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.NONE, V411IssuesFilterLevel.None);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.LOW, V411IssuesFilterLevel.Low);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.MEDIUM, V411IssuesFilterLevel.Medium);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.HIGH, V411IssuesFilterLevel.High);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.POTENTIAL, V411IssuesFilterLevel.Potential);
        REVERSE_ISSUE_FILTER_LEVEL_MAP.put(Reports.IssuesFilter.Level.ALL, V411IssuesFilterLevel.All);

        REVERSE_ISSUE_FILTER_CONDITION_MAP.put(Reports.IssuesFilter.Condition.NONE, V411IssuesFilterExploitationCondition.None);
        REVERSE_ISSUE_FILTER_CONDITION_MAP.put(Reports.IssuesFilter.Condition.NOCONDITION, V411IssuesFilterExploitationCondition.NoCondition);
        REVERSE_ISSUE_FILTER_CONDITION_MAP.put(Reports.IssuesFilter.Condition.UNDERCONDITION, V411IssuesFilterExploitationCondition.UnderCondition);
        REVERSE_ISSUE_FILTER_CONDITION_MAP.put(Reports.IssuesFilter.Condition.ALL, V411IssuesFilterExploitationCondition.All);

        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.NONE, V411IssuesFilterScanMode.None);
        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.FROMENTRYPOINT, V411IssuesFilterScanMode.FromEntryPoint);
        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.FROMPUBLICPROTECTED, V411IssuesFilterScanMode.FromPublicProtected);
        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.FROMOTHER, V411IssuesFilterScanMode.FromOther);
        REVERSE_ISSUE_FILTER_SCANMODE_MAP.put(Reports.IssuesFilter.ScanMode.ALL, V411IssuesFilterScanMode.All);

        REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP.put(Reports.IssuesFilter.ActualStatus.ISNEW, V411IssuesFilterActualStatus.ISNEW);
        REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP.put(Reports.IssuesFilter.ActualStatus.NOTISNEW, V411IssuesFilterActualStatus.NOTISNEW);
        REVERSE_ISSUE_FILTER_ACTUALSTATUS_MAP.put(Reports.IssuesFilter.ActualStatus.ALL, V411IssuesFilterActualStatus.ALL);

        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.UNDEFINED, V411IssuesFilterConfirmationStatus.Undefined);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.NONE, V411IssuesFilterConfirmationStatus.None);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.APPROVED, V411IssuesFilterConfirmationStatus.Approved);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.AUTOAPPROVED, V411IssuesFilterConfirmationStatus.AutoApproved);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.DISCARDED, V411IssuesFilterConfirmationStatus.Discarded);
        REVERSE_ISSUE_FILTER_CONFIRMATIONSTATUS_MAP.put(Reports.IssuesFilter.ApprovalState.ALL, V411IssuesFilterConfirmationStatus.All);

        REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.put(Reports.IssuesFilter.SuppressStatus.NONE, V411IssuesFilterSuppressStatus.None);
        REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.put(Reports.IssuesFilter.SuppressStatus.SUPPRESSED, V411IssuesFilterSuppressStatus.Suppressed);
        REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.put(Reports.IssuesFilter.SuppressStatus.EXCEPTSUPPRESSED, V411IssuesFilterSuppressStatus.ExceptSuppressed);
        REVERSE_ISSUE_FILTER_SUPPRESSSTATUS_MAP.put(Reports.IssuesFilter.SuppressStatus.ALL, V411IssuesFilterSuppressStatus.All);

        REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.put(Reports.IssuesFilter.SourceType.NONE, V411IssuesFilterSourceType.None);
        REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.put(Reports.IssuesFilter.SourceType.STATIC, V411IssuesFilterSourceType.Static);
        REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.put(Reports.IssuesFilter.SourceType.BLACKBOX, V411IssuesFilterSourceType.BlackBox);
        REVERSE_ISSUE_FILTER_SOURCETYPE_MAP.put(Reports.IssuesFilter.SourceType.ALL, V411IssuesFilterSourceType.All);
    }

    @NonNull
    public static V411IssuesFilter convert(@NonNull final Reports.IssuesFilter filter) {
        V411IssuesFilter res = new V411IssuesFilter();
        // No filters are defined - set ALL value
        if (null == filter.getIssueLevel() && isEmpty(filter.getIssueLevels()))
            res.setIssueLevel(V411IssuesFilterLevel.All.getValue());
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
            res.setExploitationCondition(V411IssuesFilterExploitationCondition.All.getValue());
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
            res.setScanMode(V411IssuesFilterScanMode.All.getValue());
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
            res.setSuppressStatus(V411IssuesFilterSuppressStatus.All.getValue());
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
            res.setConfirmationStatus(V411IssuesFilterConfirmationStatus.All.getValue());
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
            res.setSourceType(V411IssuesFilterSourceType.All.getValue());
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
                ? V411IssuesFilterActualStatus.ALL
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
    public static List<V411IssuesFilterType> convert(@NonNull final List<String> types) {
        List<V411IssuesFilterType> res = new ArrayList<>();
        for (String type : types)
            res.add(new V411IssuesFilterType().value(type).enable(true));
        return res;
    }
}
