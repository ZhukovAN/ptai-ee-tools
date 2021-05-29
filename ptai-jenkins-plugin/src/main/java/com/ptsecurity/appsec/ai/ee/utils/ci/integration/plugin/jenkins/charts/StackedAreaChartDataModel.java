package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StackedAreaChartDataModel {
    @Getter
    @Setter
    @Builder
    @RequiredArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Title {
        @NonNull
        @JsonProperty
        protected String text;
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
        @NonNull
        @JsonProperty
        @Builder.Default
        public List<String> data = new ArrayList<>();
    }

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
    protected StackedAreaChartDataModel.Toolbox toolbox;

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
        protected boolean containLabel = true;
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
        protected boolean boundaryGap = false;
        @JsonProperty
        @Builder.Default
        protected List<String> data = new ArrayList<>();
    }

    @JsonProperty
    @Builder.Default
    protected List<XAxis> xAxis = new ArrayList<>();

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class YAxis {
        @JsonProperty
        protected String type;
    }

    @JsonProperty
    @Builder.Default
    protected List<YAxis> yAxis = new ArrayList<>();

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
}
