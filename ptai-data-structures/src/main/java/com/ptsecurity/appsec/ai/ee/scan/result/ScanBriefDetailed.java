package com.ptsecurity.appsec.ai.ee.scan.result;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Class that extends ScanBrief with data required to build charts
 */
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class ScanBriefDetailed extends ScanBrief {
    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Details {
        @Getter
        @Setter
        @SuperBuilder
        @NoArgsConstructor
        @AllArgsConstructor
        public static class ChartData {

            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
            @AllArgsConstructor
            public static class BaseIssueCountFields {
                /**
                 * See {@link BaseIssue#getLevel()} description
                 */
                @JsonProperty
                protected BaseIssue.Level level;
                /**
                 * See {@link BaseIssue#getClazz()} description
                 */
                @JsonProperty("class")
                protected BaseIssue.Type clazz;

                /**
                 * Issue title
                 */
                @JsonProperty
                protected Map<Reports.Locale, String> title;

                /**
                 * See {@link BaseIssue#getFavorite()} description
                 */
                @JsonProperty("isFavorite")
                protected Boolean favorite;

                /**
                 * See {@link BaseIssue#getSuspected()} description
                 */
                @JsonProperty("isSuspected")
                protected Boolean suspected;

                /**
                 * See {@link BaseIssue#getSuppressed()} description
                 */
                @JsonProperty("isSuppressed")
                protected Boolean suppressed;

                /**
                 * See {@link BaseIssue#getApprovalState()} description
                 */
                @JsonProperty("approvalState")
                protected BaseIssue.ApprovalState approvalState;

                /**
                 * See {@link BaseIssue#getNewInScanResultId()} description
                 */
                @JsonProperty("newInScanResultId")
                protected UUID newInScanResultId;

                /**
                 * See {@link VulnerabilityIssue#getScanMode()} description
                 */
                @Builder.Default
                @JsonProperty("scanMode")
                protected VulnerabilityIssue.ScanMode scanMode = VulnerabilityIssue.ScanMode.NONE;
            }

            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
            @AllArgsConstructor
            public static class BaseIssueCount extends BaseIssueCountFields {
                @JsonProperty
                protected Long count;
            }

            @JsonProperty
            @Builder.Default
            protected List<BaseIssueCount> baseIssueDistributionData = new ArrayList<>();

        }

        @JsonProperty
        @Builder.Default
        protected ChartData chartData = ChartData.builder().build();
    }

    @Getter
    @Setter
    @JsonProperty
    protected Details details;

    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Performance {
        @JsonProperty
        @Builder.Default
        protected Map<Stage, String> stages = new HashMap<>();
    }

    @Getter
    @Setter
    @JsonProperty
    @Builder.Default
    protected Performance performance = new Performance();

    public static ScanBriefDetailed create(@NonNull final ScanBrief scanResult, @NonNull final Performance performance) {
        return ScanBriefDetailed.builder()
                .id(scanResult.id)
                .ptaiServerUrl(scanResult.ptaiServerUrl)
                .projectId(scanResult.projectId)
                .projectName(scanResult.projectName)
                .scanSettings(scanResult.scanSettings)
                .useAsyncScan(scanResult.useAsyncScan)
                .policyState(scanResult.policyState)
                .ptaiAgentVersion(scanResult.ptaiAgentVersion)
                .ptaiServerVersion(scanResult.ptaiServerVersion)
                .statistics(scanResult.statistics)
                .state(scanResult.state)
                .performance(performance)
                .build();
    }

    public static ScanBriefDetailed create(@NonNull final ScanResult scanResult, @NonNull final Performance performance) {
        return ScanBriefDetailed.builder()
                .id(scanResult.id)
                .ptaiServerUrl(scanResult.ptaiServerUrl)
                .projectId(scanResult.projectId)
                .projectName(scanResult.projectName)
                .scanSettings(scanResult.scanSettings)
                .useAsyncScan(scanResult.useAsyncScan)
                .policyState(scanResult.policyState)
                .ptaiAgentVersion(scanResult.ptaiAgentVersion)
                .ptaiServerVersion(scanResult.ptaiServerVersion)
                .statistics(scanResult.statistics)
                .state(scanResult.state)
                .performance(performance)
                .details(Details.builder()
                        .chartData(Details.ChartData.builder()
                                .baseIssueDistributionData(createBaseIssueDistributionData(scanResult))
                                .build())
                        .build())
                .build();

    }

    public static List<Details.ChartData.BaseIssueCount> createBaseIssueDistributionData(@NonNull final ScanResult scanResult) {
        Map<Details.ChartData.BaseIssueCountFields, Long> distribution = scanResult.getIssues().stream()
                .collect(Collectors.groupingBy(
                        issue -> {
                            Map<Reports.Locale, String> title = new HashMap<>();
                            for (Reports.Locale locale : Reports.Locale.values()) {
                                String titleStr = scanResult.getI18n().get(issue.getTypeId()).get(locale).getTitle();
                                title.put(locale, titleStr);
                            }
                            return Details.ChartData.BaseIssueCountFields.builder()
                                    .approvalState(issue.getApprovalState())
                                    .clazz(issue.getClazz())
                                    .title(title)
                                    .favorite(issue.getFavorite())
                                    .level(issue.getLevel())
                                    .newInScanResultId(issue.getNewInScanResultId())
                                    .suppressed(issue.getSuppressed())
                                    .suspected(issue.getSuspected())
                                    .suppressed(issue.getSuppressed())
                                    .scanMode(issue instanceof VulnerabilityIssue
                                            ? ((VulnerabilityIssue) issue).getScanMode()
                                            : VulnerabilityIssue.ScanMode.FROM_OTHER)
                                    .build();
                        },
                        Collectors.counting()));
        Comparator<Details.ChartData.BaseIssueCount> compareLevelTypeAndCount = Comparator
                .comparing(Details.ChartData.BaseIssueCount::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue).reversed())
                .thenComparing(Details.ChartData.BaseIssueCount::getCount, Comparator.reverseOrder());
        List<Details.ChartData.BaseIssueCount> res = new ArrayList<>();

        for (Details.ChartData.BaseIssueCountFields key : distribution.keySet())
            res.add(Details.ChartData.BaseIssueCount.builder()
                    .approvalState(key.getApprovalState())
                    .clazz(key.getClazz())
                    .favorite(key.getFavorite())
                    .level(key.getLevel())
                    .newInScanResultId(key.getNewInScanResultId())
                    .title(key.getTitle())
                    .suspected(key.getSuspected())
                    .suppressed(key.getSuppressed())
                    .count(distribution.get(key))
                    .scanMode(key.getScanMode())
                    .build());
        return res.stream().sorted(compareLevelTypeAndCount).collect(Collectors.toList());
    }
}
