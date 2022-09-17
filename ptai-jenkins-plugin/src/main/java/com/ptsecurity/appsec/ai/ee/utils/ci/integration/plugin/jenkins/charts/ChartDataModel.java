package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue.Level;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobMultipleResults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils.I18nHelper;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.util.*;

@Getter
@Setter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ChartDataModel extends BaseJsonChartDataModel {
    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Legend {
        @NonNull
        @JsonProperty
        @Builder.Default
        public List<String> data = new ArrayList<>();
    }

    @NonNull
    @JsonProperty
    @Builder.Default
    protected Legend legend = Legend.builder().build();

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Axis {
        @JsonProperty
        @Builder.Default
        protected List<String> data = new ArrayList<>();
    }

    // ECharts's stacked area chart data model uses "xAxis" and "yAxis"
    // names. But if we simply name field "xAxis" then Lombok's generated
    // getter will be named as getXAxis. During POJOPropertiesCollector.collectAll
    // call that getter will be recognized as matching to xaxis or XAxis field
    // name (it depends on USE_STD_BEAN_NAMING mapper feature) so that field
    // will be serialized twice; as xAxis and xaxis / XAxis. So we need to
    // xplicitly set JSON property name and use neutral field name
    @Builder.Default
    @JsonProperty("xAxis")
    protected List<Axis> xaxis = new ArrayList<>();

    @Builder.Default
    @JsonProperty("yAxis")
    protected List<Axis> yaxis = new ArrayList<>();

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Series {
        @JsonProperty
        protected String name;

        @Getter
        @Setter
        @Builder
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class DataItem {
            @JsonProperty
            protected Long value;

            @Getter
            @Setter
            @Builder
            @JsonInclude(JsonInclude.Include.NON_NULL)
            public static class ItemStyle {
                @JsonProperty
                protected String color;
            }

            @JsonProperty
            protected ItemStyle itemStyle;
        }

        @JsonProperty
        @Builder.Default
        protected List<DataItem> data = new ArrayList<>();

        @JsonProperty
        protected DataItem.ItemStyle itemStyle;
    }

    @JsonProperty
    @Builder.Default
    protected List<Series> series = new ArrayList<>();

    public static ChartDataModel create(@NonNull final List<AstJobMultipleResults.BuildScanBriefDetailed> scanResultList) {
        // Prepare X-axis
        ChartDataModel.Axis xAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Axis yAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Legend legend = ChartDataModel.Legend.builder().build();
        // Sort scan results by build number
        scanResultList.sort(Comparator.comparing(AstJobMultipleResults.BuildScanBriefDetailed::getBuildNumber));
        // Prepare series to fill with data
        List<Series> vulnerabilityTypeSeries = new ArrayList<>();
        for (Level level : Level.values()) {
            // SCA isues may have NONE vulnerability level so we can't ignore them
            // if (Level.NONE.equals(level)) continue;
            legend.data.add(I18nHelper.i18n(level));
            ChartDataModel.Series series = Series.builder()
                    .name(I18nHelper.i18n(level))
                    .itemStyle(Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(LEVEL_COLORS.get(level)))
                            .build())
                    .build();
            // Pre-fill series with zeroes
            for (int i = 0 ; i < scanResultList.size() ; i++) {
                long count = 0;
                do {
                    ScanBriefDetailed issues = scanResultList.get(i).getScanBriefDetailed();
                    if (null == issues) break;
                    if (!Optional.of(issues)
                            .map(ScanBriefDetailed::getDetails)
                            .map(ScanBriefDetailed.Details::getChartData)
                            .map(ScanBriefDetailed.Details.ChartData::getBaseIssueDistributionData).isPresent()) break;
                    // Count non-discarded vulnerabilities of a givel level
                    count = issues.getDetails().getChartData().getBaseIssueDistributionData().stream()
                            .filter(baseIssue -> level.equals(baseIssue.getLevel()))
                            .filter(baseIssue -> BaseIssue.ApprovalState.DISCARD != baseIssue.getApprovalState())
                            .count();
                } while (false);
                series.data.add(Series.DataItem.builder().value(count).build());
            }
            vulnerabilityTypeSeries.add(series);
        }

        for (AstJobMultipleResults.BuildScanBriefDetailed item : scanResultList)
            // As Jenkins itself prefixes build numbers with "#" sign, let's do the same for chart
            xAxis.data.add(item.getBuildNumber().toString());
        return ChartDataModel.builder()
                .legend(legend)
                .xaxis(Collections.singletonList(xAxis))
                .yaxis(Collections.singletonList(yAxis))
                .series(vulnerabilityTypeSeries)
                .build();
    }
}
