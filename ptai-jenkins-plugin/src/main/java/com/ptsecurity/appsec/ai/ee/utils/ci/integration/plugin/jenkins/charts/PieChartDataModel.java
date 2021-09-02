package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PieChartDataModel extends BaseJsonChartDataModel {
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
            protected String name;

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
    }

    @JsonProperty
    @Builder.Default
    protected List<Series> series = new ArrayList<>();
}
