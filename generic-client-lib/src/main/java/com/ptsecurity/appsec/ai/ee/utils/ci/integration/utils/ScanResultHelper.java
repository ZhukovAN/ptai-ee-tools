package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;

/**
 * As {@link ScanResult} is in fact a DTO class, we need to implement its processing separately
 */
public class ScanResultHelper {

    /**
     * Apply {@link com.ptsecurity.appsec.ai.ee.scan.reports.Reports.IssuesFilter} to {@link ScanResult}. Method
     * doesn't do any grouping as those are to be implemented in a scan result consumer, so only filtering is
     * being executed
     * @param scanResult Scan result that is to be filtered
     * @param filter Filter to be applied
     */
    public static void apply(@NonNull final ScanResult scanResult, final Reports.IssuesFilter filter) {
        if (null == filter) return;

        // TODO: Get rid of NONE filters

        // Filter by issue level
        Set<Reports.IssuesFilter.Level> filterLevels = new HashSet<>();
        if (null != filter.getIssueLevel()) filterLevels.add(filter.getIssueLevel());
        if (isNotEmpty(filter.getIssueLevels())) filterLevels.addAll(filter.getIssueLevels());
        // At this point filterLevels contain issue levels that are to be kept in scan result
        if (!filterLevels.isEmpty() && !filterLevels.contains(Reports.IssuesFilter.Level.ALL)) {
            Iterator<BaseIssue> iterator = scanResult.getIssues().iterator();
            while (iterator.hasNext()) {
                BaseIssue issue = iterator.next();
                if (BaseIssue.Level.HIGH.equals(issue.getLevel()) && filterLevels.contains(Reports.IssuesFilter.Level.HIGH)) continue;
                if (BaseIssue.Level.MEDIUM.equals(issue.getLevel()) && filterLevels.contains(Reports.IssuesFilter.Level.MEDIUM)) continue;
                if (BaseIssue.Level.LOW.equals(issue.getLevel()) && filterLevels.contains(Reports.IssuesFilter.Level.LOW)) continue;
                if (BaseIssue.Level.POTENTIAL.equals(issue.getLevel()) && filterLevels.contains(Reports.IssuesFilter.Level.POTENTIAL)) continue;
                if (BaseIssue.Level.NONE.equals(issue.getLevel()) && filterLevels.contains(Reports.IssuesFilter.Level.NONE)) continue;
                iterator.remove();
            }
        }

        // Filter by confirmation status
        Set<Reports.IssuesFilter.ApprovalState> approvalStates = new HashSet<>();
        if (null != filter.getConfirmationStatus()) approvalStates.add(filter.getConfirmationStatus());
        if (isNotEmpty(filter.getConfirmationStatuses())) approvalStates.addAll(filter.getConfirmationStatuses());
        // At this point approvalStates contain confirmatiion sttatuses that are to be kept in scan result
        if (!approvalStates.isEmpty() && !approvalStates.contains(Reports.IssuesFilter.ApprovalState.ALL)) {
            Iterator<BaseIssue> iterator = scanResult.getIssues().iterator();
            while (iterator.hasNext()) {
                BaseIssue issue = iterator.next();
                if (BaseIssue.ApprovalState.APPROVAL.equals(issue.getApprovalState()) && approvalStates.contains(Reports.IssuesFilter.ApprovalState.APPROVED)) continue;
                if (BaseIssue.ApprovalState.AUTO_APPROVAL.equals(issue.getApprovalState()) && approvalStates.contains(Reports.IssuesFilter.ApprovalState.AUTOAPPROVED)) continue;
                if (BaseIssue.ApprovalState.DISCARD.equals(issue.getApprovalState()) && approvalStates.contains(Reports.IssuesFilter.ApprovalState.DISCARDED)) continue;
                if (BaseIssue.ApprovalState.NOT_EXIST.equals(issue.getApprovalState()) && approvalStates.contains(Reports.IssuesFilter.ApprovalState.UNDEFINED)) continue;
                if (BaseIssue.ApprovalState.NONE.equals(issue.getApprovalState()) && approvalStates.contains(Reports.IssuesFilter.ApprovalState.NONE)) continue;
                iterator.remove();
            }
        }

        // Filter by exploitation condition
        Set<Reports.IssuesFilter.Condition> conditions = new HashSet<>();
        if (null != filter.getExploitationCondition()) conditions.add(filter.getExploitationCondition());
        if (isNotEmpty(filter.getExploitationConditions())) conditions.addAll(filter.getExploitationConditions());
        // At this point exploitation condition statuses contain those that are to be kept in scan result
        if (!conditions.isEmpty() && !conditions.contains(Reports.IssuesFilter.Condition.ALL)) {
            Iterator<BaseIssue> iterator = scanResult.getIssues().iterator();
            while (iterator.hasNext()) {
                BaseIssue issue = iterator.next();
                if (!BaseIssue.Type.VULNERABILITY.equals(issue.getClazz())) continue;

                VulnerabilityIssue vulnerabilityIssue = (VulnerabilityIssue) issue;
                if (StringUtils.isEmpty(vulnerabilityIssue.getConditions()) && conditions.contains(Reports.IssuesFilter.Condition.NOCONDITION)) continue;
                if (StringUtils.isNotEmpty(vulnerabilityIssue.getConditions()) && conditions.contains(Reports.IssuesFilter.Condition.UNDERCONDITION)) continue;
                iterator.remove();
            }
        }

        // Filter by suppress statuses
        Set<Reports.IssuesFilter.SuppressStatus> suppressStatuses = new HashSet<>();
        if (null != filter.getSuppressStatus()) suppressStatuses.add(filter.getSuppressStatus());
        if (isNotEmpty(filter.getSuppressStatuses())) suppressStatuses.addAll(filter.getSuppressStatuses());
        // At this point suppress statuses contain those that are to be kept in scan result
        if (!suppressStatuses.isEmpty() && !suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.ALL)) {
            Iterator<BaseIssue> iterator = scanResult.getIssues().iterator();
            while (iterator.hasNext()) {
                BaseIssue issue = iterator.next();
                if (issue.getSuppressed() && suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.SUPPRESSED)) continue;
                if (!issue.getSuppressed() && suppressStatuses.contains(Reports.IssuesFilter.SuppressStatus.EXCEPTSUPPRESSED)) continue;
                iterator.remove();
            }
        }

        // Filter by source type
        Set<Reports.IssuesFilter.SourceType> sourceTypes = new HashSet<>();
        if (null != filter.getSourceType()) sourceTypes.add(filter.getSourceType());
        if (isNotEmpty(filter.getSourceTypes())) sourceTypes.addAll(filter.getSourceTypes());
        // At this point source types contain those that are to be kept in scan result
        if (!sourceTypes.isEmpty() && !sourceTypes.contains(Reports.IssuesFilter.SourceType.ALL)) {
            Iterator<BaseIssue> iterator = scanResult.getIssues().iterator();
            while (iterator.hasNext()) {
                BaseIssue issue = iterator.next();
                if (!BaseIssue.Type.BLACKBOX.equals(issue.getClazz()) && sourceTypes.contains(Reports.IssuesFilter.SourceType.STATIC)) continue;
                if (BaseIssue.Type.BLACKBOX.equals(issue.getClazz()) && sourceTypes.contains(Reports.IssuesFilter.SourceType.BLACKBOX)) continue;
                iterator.remove();
            }
        }

        // Filter by scan mode
        Set<Reports.IssuesFilter.ScanMode> scanModes = new HashSet<>();
        if (null != filter.getScanMode()) scanModes.add(filter.getScanMode());
        if (isNotEmpty(filter.getScanModes())) scanModes.addAll(filter.getScanModes());
        // At this point scan modes contain those that are to be kept in scan result
        if (!scanModes.isEmpty() && !scanModes.contains(Reports.IssuesFilter.ScanMode.ALL)) {
            Iterator<BaseIssue> iterator = scanResult.getIssues().iterator();
            while (iterator.hasNext()) {
                BaseIssue issue = iterator.next();
                if (BaseIssue.Type.VULNERABILITY.equals(issue.getClazz())) {
                    VulnerabilityIssue vulnerabilityIssue = (VulnerabilityIssue) issue;
                    if (VulnerabilityIssue.ScanMode.FROM_OTHER.equals(vulnerabilityIssue.getScanMode()) && scanModes.contains(Reports.IssuesFilter.ScanMode.FROMOTHER)) continue;
                    if (VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT.equals(vulnerabilityIssue.getScanMode()) && scanModes.contains(Reports.IssuesFilter.ScanMode.FROMENTRYPOINT)) continue;
                    if (VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED.equals(vulnerabilityIssue.getScanMode()) && scanModes.contains(Reports.IssuesFilter.ScanMode.FROMPUBLICPROTECTED)) continue;
                } else
                if (scanModes.contains(Reports.IssuesFilter.ScanMode.FROMOTHER)) continue;
                iterator.remove();
            }
        }
        // Filter by new / old status
        Set<Reports.IssuesFilter.ActualStatus> actualStatuses = new HashSet<>();
        if (null != filter.getActualStatus()) actualStatuses.add(filter.getActualStatus());
        // At this point new / old statuses contain those that are to be kept in scan result
        if (!actualStatuses.isEmpty() && !actualStatuses.contains(Reports.IssuesFilter.ActualStatus.ALL)) {
            Iterator<BaseIssue> iterator = scanResult.getIssues().iterator();
            while (iterator.hasNext()) {
                BaseIssue issue = iterator.next();
                if (scanResult.getId().equals(issue.getNewInScanResultId()) && actualStatuses.contains(Reports.IssuesFilter.ActualStatus.ISNEW)) continue;
                if (!scanResult.getId().equals(issue.getNewInScanResultId()) && actualStatuses.contains(Reports.IssuesFilter.ActualStatus.NOTISNEW)) continue;
                iterator.remove();
            }
        }

        Iterator<BaseIssue> iterator = scanResult.getIssues().iterator();
        while (iterator.hasNext()) {
            BaseIssue issue = iterator.next();
            boolean remove = true;
            do {
                if (BaseIssue.Type.VULNERABILITY.equals(issue.getClazz())) {
                    VulnerabilityIssue vulnerabilityIssue = (VulnerabilityIssue) issue;
                    if (Boolean.TRUE.equals(filter.getHideSecondOrder()) && Boolean.TRUE.equals(vulnerabilityIssue.getSecondOrder())) break;
                }
                if (Boolean.TRUE.equals(filter.getHideSuspected()) && Boolean.TRUE.equals(issue.getSuspected())) break;
                remove = false;
            } while (false);
            if (remove) iterator.remove();
        }
        // Ignore "byXxx" filter options as those aren't applicable to JSON reports
    }
}
