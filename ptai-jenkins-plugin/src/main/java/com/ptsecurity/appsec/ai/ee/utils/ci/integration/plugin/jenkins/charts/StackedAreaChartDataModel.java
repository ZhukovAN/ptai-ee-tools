package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.IssueLevel;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.IssuesModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import lombok.*;
import org.apache.commons.lang3.tuple.Triple;

import java.time.LocalDateTime;
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
    public static class Title {
        @NonNull
        @JsonProperty
        protected String text;

        @JsonProperty
        @Builder.Default
        protected String left = "center";

        @JsonProperty
        @Builder.Default
        protected Boolean show = true;
    }

    @NonNull
    @JsonProperty
    protected Title title;

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Tooltip {
        @NonNull
        @JsonProperty
        protected String trigger;

        @Getter
        @Setter
        @Builder
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class AxisPointer {
            @NonNull
            @JsonProperty
            protected String type;

            @Getter
            @Setter
            @Builder
            @JsonInclude(JsonInclude.Include.NON_NULL)
            public static class Label {
                @NonNull
                @JsonProperty
                protected String backgroundColor;
            }

            @NonNull
            @JsonProperty
            protected Label label;
        }

        @NonNull
        @JsonProperty
        protected AxisPointer axisPointer;
    }

    @NonNull
    @JsonProperty
    protected Tooltip tooltip;

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Legend {
        @JsonProperty
        @Builder.Default
        protected String top = "bottom";

        @JsonProperty
        @Builder.Default
        protected String left = "center";

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
    public static class Toolbox {
        @Getter
        @Setter
        @Builder
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class Feature {
            @Getter
            @Setter
            @Builder
            @JsonInclude(JsonInclude.Include.NON_NULL)
            public static class SaveAsImage {
                @NonNull
                @JsonProperty
                @Builder.Default
                protected Boolean show = false;
            }

            @NonNull
            @JsonProperty
            protected SaveAsImage saveAsImage;
        }

        @NonNull
        @JsonProperty
        protected Feature feature;
    }

    @NonNull
    @JsonProperty
    protected Toolbox toolbox;

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Grid {
        @JsonProperty
        protected String left;
        @JsonProperty
        protected String right;
        @JsonProperty
        protected String top;
        @JsonProperty
        protected String bottom;
        @JsonProperty
        @Builder.Default
        protected Boolean containLabel = true;
    }

    @NonNull
    @JsonProperty
    protected Grid grid;

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class XAxis {
        @JsonProperty
        protected String type;
        @JsonProperty
        @Builder.Default
        protected Boolean boundaryGap = false;
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
    protected List<XAxis> xaxis = new ArrayList<>();

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class YAxis {
        @JsonProperty
        protected String type;
    }

    @Builder.Default
    @JsonProperty("yAxis")
    protected List<YAxis> yaxis = new ArrayList<>();

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Series {
        @JsonProperty
        protected String name;
        @JsonProperty
        protected String type;
        @JsonProperty
        protected String stack;

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

        @Getter
        @Setter
        @Builder
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class AreaStyle {
        }
        @JsonProperty
        protected AreaStyle areaStyle;

        @Getter
        @Setter
        @Builder
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class Emphasis {
            @JsonProperty
            protected String focus;
        }
        @JsonProperty
        protected Emphasis emphasis;

        @JsonProperty
        @Builder.Default
        protected List<Long> data = new ArrayList<>();
    }

    @JsonProperty
    @Builder.Default
    protected List<Series> series = new ArrayList<>();

    public static StackedAreaChartDataModel create(@NonNull final List<Triple<Integer, LocalDateTime, IssuesModel>> issuesModelList) {
        // Prepare X-axis
        StackedAreaChartDataModel.XAxis xAxis = StackedAreaChartDataModel.XAxis.builder()
                .type("category")
                .boundaryGap(false)
                .build();
        StackedAreaChartDataModel.YAxis yAxis = StackedAreaChartDataModel.YAxis.builder()
                .type("value")
                .build();
        StackedAreaChartDataModel.Legend legend = StackedAreaChartDataModel.Legend.builder().build();
        // Prepare series to fill with data
        Map<IssueLevel, Series> vulnerabilityTypeSeries = new HashMap<>();
        for (IssueLevel level : IssueLevel.values()) {
            if (IssueLevel.None.equals(level)) continue;

            legend.data.add(level.name());
            StackedAreaChartDataModel.Series series = StackedAreaChartDataModel.Series.builder()
                    .name(level.name())
                    .type("line")
                    .stack("0")
                    .itemStyle(ITEM_STYLE_MAP.get(level))
                    .areaStyle(new StackedAreaChartDataModel.Series.AreaStyle())
                    .emphasis(new StackedAreaChartDataModel.Series.Emphasis("series"))
                    .build();
            vulnerabilityTypeSeries.put(level, series);
        }

        issuesModelList.sort((u1, u2) -> u1.getLeft().compareTo(u2.getLeft()));

        for (Triple<Integer, LocalDateTime, IssuesModel> item : issuesModelList) {
            // As Jenkins itself prefixes build numbers with "#" sign, let's do the same for chart
            xAxis.data.add("#" + item.getLeft().toString());
            IssuesModel issues = item.getRight();
            for (IssueLevel level : IssueLevel.values()) {
                if (IssueLevel.None.equals(level)) continue;
                if (null == issues.getIssues()) continue;
                long count = issues.getIssues().stream().filter(issueBase -> level.equals(issueBase.getLevel())).count();
                vulnerabilityTypeSeries.get(level).data.add(count);
            }
        }
        StackedAreaChartDataModel model = StackedAreaChartDataModel.builder()
                .title(Title.builder()
                        .text(Resources.i18n_ast_result_charts_trend_caption())
                        .show(false)
                        .build())
                .tooltip(StackedAreaChartDataModel.Tooltip.builder()
                        .trigger("axis")
                        .axisPointer(StackedAreaChartDataModel.Tooltip.AxisPointer.builder()
                                .type("cross")
                                .label(StackedAreaChartDataModel.Tooltip.AxisPointer.Label.builder()
                                        .backgroundColor("#6a7985")
                                        .build())
                                .build())
                        .build())
                .legend(legend)
                .toolbox(StackedAreaChartDataModel.Toolbox.builder()
                        .feature(StackedAreaChartDataModel.Toolbox.Feature.builder()
                                .saveAsImage(Toolbox.Feature.SaveAsImage.builder().build())
                                .build())
                        .build())
                .grid(StackedAreaChartDataModel.Grid.builder()
                        .bottom("25")
                        .top("10")
                        .left("20")
                        .right("10")
                        .containLabel(true)
                        .build())
                .xaxis(Collections.singletonList(xAxis))
                .yaxis(Collections.singletonList(yAxis))
                .series(new ArrayList<>(vulnerabilityTypeSeries.values()))
                .build();
        return model;
    }
}
