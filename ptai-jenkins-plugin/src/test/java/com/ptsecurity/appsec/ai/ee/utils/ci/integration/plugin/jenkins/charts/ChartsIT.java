package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdScalarDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.StackedAreaChartDataModel.Title;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.*;

@DisplayName("AST results charts generation integration tests")
@Tag("integration")
class ChartsIT extends BaseIT {
    /**
     * Custom deserializer for auto-generated {@link IssueLevel} class. Need to implement
     * this one as standard EnumDeserializer supports only enums with sequential integer
     * values starting with zero and lacks ability to deserialize values like 10 / 20 / 30 etc
     */
    public static class IssueLevelDeserializer extends StdScalarDeserializer<IssueLevel> {

        public IssueLevelDeserializer() {
            this(null);
        }

        @Override
        public IssueLevel deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            return IssueLevel.fromValue(p.getIntValue());
        }

        public IssueLevelDeserializer(Class<?> vc) {
            super(vc);
        }
    }

    @DisplayName("Generate vulnerability level distribution chart for randomly chosen scan result")
    @Test
    @SneakyThrows
    public void test() {
        // Create IssuesModel deserializer
        ObjectMapper mapper = new ObjectMapper();
        // Need this as JSON report contains "Descriptions" while IssuesModel have "descriptions"
        mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES);
        mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS);
        // Need this as JSON report contains fields like "link" that are missing from IssueDescriptionModel
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        SimpleModule module = new SimpleModule();
        module.addDeserializer(IssueLevel.class, new IssueLevelDeserializer());
        mapper.registerModule(module);

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
        Map<IssueLevel, StackedAreaChartDataModel.Series> vulnerabilityTypeSeries = new HashMap<>();
        for (IssueLevel level : IssueLevel.values()) {
            if (IssueLevel.None.equals(level)) continue;

            legend.data.add(level.name());
            StackedAreaChartDataModel.Series series = StackedAreaChartDataModel.Series.builder()
                    .name(level.name())
                    .type("line")
                    .stack("0")
                    .areaStyle(new StackedAreaChartDataModel.Series.AreaStyle())
                    .emphasis(new StackedAreaChartDataModel.Series.Emphasis("series"))
                    .build();
            vulnerabilityTypeSeries.put(level, series);
        }
        // Get random scan result
        ScanResult randomScanResult = getRandomScanResult();
        Assertions.assertNotNull(randomScanResult, "Randomly chosen scan result is null");
        // Get all scan results for random project
        List<ScanResult> projectScanResults = projectsApi.apiProjectsProjectIdScanResultsGet(randomScanResult.getProjectId(), AuthScopeType.ACCESSTOKEN);
        projectScanResults.sort(Comparator.comparing(ScanResult::getScanDate));
        for (ScanResult scanResult : projectScanResults) {
            File json = projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(scanResult.getProjectId(), scanResult.getId(), null);
            IssuesModel issues = mapper.readValue(json, IssuesModel.class);
            xAxis.data.add(scanResult.getScanDate());
            for (IssueLevel level : IssueLevel.values()) {
                if (IssueLevel.None.equals(level)) continue;
                long count = issues.getIssues().stream().filter(issueBase -> level.equals(issueBase.getLevel())).count();
                vulnerabilityTypeSeries.get(level).data.add(Long.valueOf(count));
            }
        }
        StackedAreaChartDataModel model = StackedAreaChartDataModel.builder()
                .title(new Title("PT AI results processing trend"))
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
                                .saveAsImage(new StackedAreaChartDataModel.Toolbox.Feature.SaveAsImage())
                                .build())
                        .build())
                .grid(StackedAreaChartDataModel.Grid.builder()
                        .bottom("3%")
                        .top("3%")
                        .left("3%")
                        .right("3%")
                        .containLabel(true)
                        .build())
                .xAxis(Arrays.asList(xAxis))
                .yAxis(Arrays.asList(yAxis))
                .series(new ArrayList<>(vulnerabilityTypeSeries.values()))
                .build();
        String modelJson = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(model);
        System.out.println(modelJson);
   }
}
