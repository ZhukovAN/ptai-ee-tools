package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue.Level;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobMultipleResults;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.lang.WordUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

@Getter
@Setter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StackedAreaChartDataModel extends BaseJsonChartDataModel {
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
    protected Legend legend;

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

        @JsonProperty
        @Builder.Default
        protected List<Long> data = new ArrayList<>();
    }

    @JsonProperty
    @Builder.Default
    protected List<Series> series = new ArrayList<>();

    public static StackedAreaChartDataModel create(@NonNull final List<AstJobMultipleResults.BuildScanBriefDetailed> scanResultList) {
        // Prepare X-axis
        StackedAreaChartDataModel.Axis xAxis = StackedAreaChartDataModel.Axis.builder().build();
        StackedAreaChartDataModel.Axis yAxis = StackedAreaChartDataModel.Axis.builder().build();
        StackedAreaChartDataModel.Legend legend = StackedAreaChartDataModel.Legend.builder().build();
        // Sort scan results by build number
        scanResultList.sort(Comparator.comparing(AstJobMultipleResults.BuildScanBriefDetailed::getBuildNumber));
        // Prepare series to fill with data
        List<Series> vulnerabilityTypeSeries = new ArrayList<>();
        for (Level level : Level.values()) {
            if (Level.NONE.equals(level)) continue;
            legend.data.add(level.name());
            StackedAreaChartDataModel.Series series = StackedAreaChartDataModel.Series.builder()
                    .name(level.name())
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
                series.data.add(count);
            }
            vulnerabilityTypeSeries.add(series);
        }

        for (AstJobMultipleResults.BuildScanBriefDetailed item : scanResultList)
            // As Jenkins itself prefixes build numbers with "#" sign, let's do the same for chart
            xAxis.data.add(item.getBuildNumber().toString());
        return StackedAreaChartDataModel.builder()
                .legend(legend)
                .xaxis(Collections.singletonList(xAxis))
                .yaxis(Collections.singletonList(yAxis))
                .series(vulnerabilityTypeSeries)
                .build();
    }
}
