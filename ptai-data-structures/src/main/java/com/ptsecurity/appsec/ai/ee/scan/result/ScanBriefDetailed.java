package com.ptsecurity.appsec.ai.ee.scan.result;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Class that extends ScanBrief with data required to build charts
 */
@SuperBuilder
@NoArgsConstructor
public class ScanBriefDetailed extends ScanBrief {
    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    public static class Details {
        @Getter
        @Setter
        @SuperBuilder
        @NoArgsConstructor
        public static class ChartData {

            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
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
                 * See {@link BaseIssue#getTitle()} description
                 */
                @JsonProperty
                protected String title;

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
            }

            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
            public static class BaseIssueCount extends BaseIssueCountFields {
                @JsonProperty
                protected Long count;
            }

            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
            public static class SeverityCount {
                @JsonProperty
                protected BaseIssue.Level level;

                @JsonProperty
                protected Long count;
            }

            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
            public static class SeverityTypeCount {
                @JsonProperty
                protected BaseIssue.Level level;
                @JsonProperty
                protected String title;
                @JsonProperty
                protected Long count;
            }

            @JsonProperty
            @Builder.Default
            protected List<BaseIssueCount> baseIssueDistributionData = new ArrayList<>();

            @JsonProperty
            @Builder.Default
            protected List<SeverityCount> severityDistributionData = new ArrayList<>();

            @JsonProperty
            @Builder.Default
            protected List<SeverityTypeCount> severityTypeDistributionData = new ArrayList<>();
        }

        @JsonProperty
        @Builder.Default
        protected ChartData chartData = ChartData.builder().build();
    }

    @Getter
    @Setter
    @JsonProperty
    protected Details details;

    public static ScanBriefDetailed create(@NonNull final ScanResult scanResult) {
        return ScanBriefDetailed.builder()
                .id(scanResult.id)
                .projectId(scanResult.projectId)
                .projectName(scanResult.projectName)
                .scanSettings(scanResult.scanSettings)
                .policyState(scanResult.policyState)
                .ptaiAgentVersion(scanResult.ptaiAgentVersion)
                .ptaiServerVersion(scanResult.ptaiServerVersion)
                .statistic(scanResult.statistic)
                .state(scanResult.state)
                .details(Details.builder()
                        .chartData(Details.ChartData.builder()
                                .baseIssueDistributionData(createBaseIssueDistributionData(scanResult))
                                .severityDistributionData(createSeverityDistributionData(scanResult))
                                .severityTypeDistributionData(createSeverityTypeDistributionData(scanResult))
                                .build())
                        .build())
                .build();

    }

    public static List<Details.ChartData.BaseIssueCount> createBaseIssueDistributionData(@NonNull final ScanResult scanResult) {
        Map<Details.ChartData.BaseIssueCountFields, Long> distribution = scanResult.getIssues().stream()
                .collect(Collectors.groupingBy(
                        issue -> Details.ChartData.BaseIssueCountFields.builder()
                                .approvalState(issue.getApprovalState())
                                .clazz(issue.getClazz())
                                .title(issue.getTitle())
                                .favorite(issue.getFavorite())
                                .level(issue.getLevel())
                                .newInScanResultId(issue.getNewInScanResultId())
                                .suppressed(issue.getSuppressed())
                                .suspected(issue.getSuspected())
                                .suppressed(issue.getSuppressed())
                                .build(),
                        Collectors.counting()));
        Comparator<Details.ChartData.BaseIssueCount> compareLevelTypeAndCount = Comparator
                .comparing(Details.ChartData.BaseIssueCount::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue).reversed())
                .thenComparing(Details.ChartData.BaseIssueCount::getCount, Comparator.reverseOrder())
                .thenComparing(Details.ChartData.BaseIssueCount::getTitle);
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
                    .build());
        return res.stream().sorted(compareLevelTypeAndCount).collect(Collectors.toList());
    }

    public static List<Details.ChartData.SeverityCount> createSeverityDistributionData(@NonNull final ScanResult scanResult) {
        Map<BaseIssue.Level, Long> distribution = scanResult.getIssues().stream()
                .collect(Collectors.groupingBy(
                        BaseIssue::getLevel,
                        Collectors.counting()));
        List<Details.ChartData.SeverityCount> res = new ArrayList<>();

        Comparator<Details.ChartData.SeverityCount> compareLevelAndCount = Comparator
                .comparing(Details.ChartData.SeverityCount::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue).reversed())
                .thenComparing(Details.ChartData.SeverityCount::getCount, Comparator.reverseOrder());

        for (BaseIssue.Level key : distribution.keySet())
            res.add(Details.ChartData.SeverityCount.builder()
                    .level(key)
                    .count(distribution.get(key)).build());
        return res.stream().sorted(compareLevelAndCount).collect(Collectors.toList());
    }

    public static List<Details.ChartData.SeverityTypeCount> createSeverityTypeDistributionData(@NonNull final ScanResult scanResult) {
        Map<Pair<BaseIssue.Level, String>, Long> distribution = scanResult.getIssues().stream()
                .collect(Collectors.groupingBy(
                        issue -> new ImmutablePair<>(issue.getLevel(), issue.getTitle()),
                        Collectors.counting()));
        Comparator<Details.ChartData.SeverityTypeCount> compareLevelTypeAndCount = Comparator
                .comparing(Details.ChartData.SeverityTypeCount::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue).reversed())
                .thenComparing(Details.ChartData.SeverityTypeCount::getCount, Comparator.reverseOrder())
                .thenComparing(Details.ChartData.SeverityTypeCount::getTitle);
        List<Details.ChartData.SeverityTypeCount> res = new ArrayList<>();

        for (Pair<BaseIssue.Level, String> key : distribution.keySet())
            res.add(Details.ChartData.SeverityTypeCount.builder()
                    .level(key.getLeft())
                    .title( key.getRight())
                    .count(distribution.get(key))
                    .build());
        return res.stream().sorted(compareLevelTypeAndCount).collect(Collectors.toList());
    }
}
