package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.ChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import hudson.model.Action;
import hudson.model.Job;
import hudson.model.Run;
import jenkins.model.Jenkins;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.*;

import static com.ptsecurity.appsec.ai.ee.scan.ScanDataPacked.Type.SCAN_BRIEF_DETAILED;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel.*;

@Slf4j
@RequiredArgsConstructor
public class AstJobTableResults implements Action {
    @Getter
    @NonNull
    private final Job<?, ?> project;

    @NonNull
    protected List<AstJobMultipleResults.BuildScanBriefDetailed> getLatestAstResults(final int number) {
        final List<? extends Run<?, ?>> builds = project.getBuilds();
        final List<AstJobMultipleResults.BuildScanBriefDetailed> scanResults = new ArrayList<>();

        int count = 0;
        for (Run<?, ?> build : builds) {
            ScanBriefDetailed scanBriefDetailed = null;
            do {
                final AstJobSingleResult action = build.getAction(AstJobSingleResult.class);
                if (null == action) break;
                if (null == action.getScanDataPacked()) break;
                ScanDataPacked scanDataPacked = action.getScanDataPacked();
                if (!scanDataPacked.getType().equals(SCAN_BRIEF_DETAILED)) break;
                scanBriefDetailed = ScanDataPacked.unpackData(scanDataPacked.getData(), ScanBriefDetailed.class);
            } while (false);

            scanResults.add(AstJobMultipleResults.BuildScanBriefDetailed.builder()
                    .buildNumber(build.getNumber())
                    .scanBriefDetailed(scanBriefDetailed)
                    .build());
            // Only chart the last N builds (max)
            count++;
            if (count == number) break;
        }
        return scanResults;
    }

    @SneakyThrows
    public String getScanDurationHistoryChart(final int resultsNumber) {
        final List<AstJobMultipleResults.BuildScanBriefDetailed> issuesModelList = getLatestAstResults(resultsNumber);
        // Prepare X-axis
        ChartDataModel.Axis xAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Axis yAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Legend legend = ChartDataModel.Legend.builder().build();
        // Sort scan results by build number
        issuesModelList.sort(Comparator.comparing(AstJobMultipleResults.BuildScanBriefDetailed::getBuildNumber));
        // Prepare series to fill with data
        List<ChartDataModel.Series> chartSeries = new ArrayList<>();
        final String scanDurationItemCaption = "DURATION";
        ChartDataModel.Series valueSeries = ChartDataModel.Series.builder()
                .name(scanDurationItemCaption)
                .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                        .color("#" + Integer.toHexString(LEVEL_COLORS.get(BaseIssue.Level.MEDIUM)))
                        .build())
                .build();
        // Pre-fill series with zeroes
        for (AstJobMultipleResults.BuildScanBriefDetailed buildScanBriefDetailed : issuesModelList) {
            long count = 0;
            do {
                ScanBriefDetailed brief = buildScanBriefDetailed.getScanBriefDetailed();
                if (!Optional.ofNullable(brief).map(ScanBriefDetailed::getStatistics).isPresent()) break;
                try {
                    Duration durationFull = Duration.parse(brief.getStatistics().getScanDurationIso8601());
                    count = durationFull.getSeconds();
                } catch (DateTimeParseException e) {
                    log.error("Failed to parse scan duration: {}", brief.getStatistics().getScanDurationIso8601());
                }
            } while (false);
            valueSeries.getData().add(ChartDataModel.Series.DataItem.builder().value(count).build());
        }
        chartSeries.add(valueSeries);
        legend.data.add(valueSeries.getName());
        for (AstJobMultipleResults.BuildScanBriefDetailed item : issuesModelList)
            // As Jenkins itself prefixes build numbers with "#" sign, let's do the same for chart
            xAxis.getData().add(item.getBuildNumber().toString());
        ChartDataModel chartDataModel = ChartDataModel.builder()
                .legend(legend)
                .xaxis(Collections.singletonList(xAxis))
                .yaxis(Collections.singletonList(yAxis))
                .series(chartSeries)
                .build();
        return BaseJsonHelper.createObjectMapper().writeValueAsString(chartDataModel);
    }

    protected ChartDataModel.Series createTotalIssuesCountSeries(@NonNull final List<AstJobMultipleResults.BuildScanBriefDetailed> issuesModelList) {
        final String totalVulnerabilitiesItemCaption = "TOTAL";
        ChartDataModel.Series res = ChartDataModel.Series.builder()
                .name(totalVulnerabilitiesItemCaption)
                .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                        .color("#d0d0d0")
                        .build())
                .build();
        for (AstJobMultipleResults.BuildScanBriefDetailed buildScanBriefDetailed : issuesModelList) {
            long count = 0;
            do {
                ScanBriefDetailed issues = buildScanBriefDetailed.getScanBriefDetailed();
                if (null == issues) break;
                if (!Optional.of(issues)
                        .map(ScanBriefDetailed::getDetails)
                        .map(ScanBriefDetailed.Details::getChartData)
                        .map(ScanBriefDetailed.Details.ChartData::getBaseIssueDistributionData).isPresent()) break;
                count = issues.getDetails().getChartData().getBaseIssueDistributionData().size();
            } while (false);
            res.getData().add(ChartDataModel.Series.DataItem.builder().value(count).build());
        }
        return res;
    }

    @SneakyThrows
    public String getApprovalHistoryChart(final int resultsNumber) {
        final List<AstJobMultipleResults.BuildScanBriefDetailed> issuesModelList = getLatestAstResults(resultsNumber);
        // Prepare X-axis
        ChartDataModel.Axis xAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Axis yAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Legend legend = ChartDataModel.Legend.builder().build();
        // Sort scan results by build number
        issuesModelList.sort(Comparator.comparing(AstJobMultipleResults.BuildScanBriefDetailed::getBuildNumber));

        List<ChartDataModel.Series> chartSeries = new ArrayList<>();
        // Add "total issues count" series and legend item
        ChartDataModel.Series totalVulnerabilityCountSeries = createTotalIssuesCountSeries(issuesModelList);
        chartSeries.add(totalVulnerabilityCountSeries);
        legend.data.add(totalVulnerabilityCountSeries.getName());

        for (AstJobMultipleResults.BuildScanBriefDetailed buildScanBriefDetailed : issuesModelList)
            // As Jenkins itself prefixes build numbers with "#" sign, let's do the same for chart
            xAxis.getData().add(buildScanBriefDetailed.getBuildNumber().toString());
        // As we need to show confirmed and rejected vulnerabilities at the very
        // bottom of the chart so can't simply iterate ApprovalState.values
        List<BaseIssue.ApprovalState> approvalStates = Arrays.asList(
                BaseIssue.ApprovalState.APPROVAL, BaseIssue.ApprovalState.DISCARD, BaseIssue.ApprovalState.AUTO_APPROVAL,
                BaseIssue.ApprovalState.NONE, BaseIssue.ApprovalState.NOT_EXIST);
        for (BaseIssue.ApprovalState value : approvalStates) {
            ChartDataModel.Series valueSeries
                    = ChartDataModel.Series.builder()
                    .name(value.name())
                    .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(APPROVAL_COLORS.get(value)))
                            .build())
                    .build();
            // Prepare series to fill with data
            for (AstJobMultipleResults.BuildScanBriefDetailed buildScanBriefDetailed : issuesModelList) {
                long count = 0;
                do {
                    ScanBriefDetailed issues = buildScanBriefDetailed.getScanBriefDetailed();
                    if (null == issues) break;
                    if (!Optional.of(issues)
                            .map(ScanBriefDetailed::getDetails)
                            .map(ScanBriefDetailed.Details::getChartData)
                            .map(ScanBriefDetailed.Details.ChartData::getBaseIssueDistributionData).isPresent()) break;
                    count = issues.getDetails().getChartData().getBaseIssueDistributionData().stream()
                            .filter(baseIssue -> value == baseIssue.getApprovalState())
                            .count();
                } while (false);
                valueSeries.getData().add(ChartDataModel.Series.DataItem.builder().value(count).build());
            }
            // Skip series with no data
            if (valueSeries.getData().stream().noneMatch(i -> i.getValue() != 0)) continue;
            chartSeries.add(valueSeries);
            legend.data.add(value.name());
        }

        ChartDataModel chartDataModel = ChartDataModel.builder()
                .legend(legend)
                .xaxis(Collections.singletonList(xAxis))
                .yaxis(Collections.singletonList(yAxis))
                .series(chartSeries)
                .build();
        return BaseJsonHelper.createObjectMapper().writeValueAsString(chartDataModel);
    }

    @SneakyThrows
    public String getTypeHistoryChart(final int resultsNumber) {
        final List<AstJobMultipleResults.BuildScanBriefDetailed> issuesModelList = getLatestAstResults(resultsNumber);
        // Prepare X-axis
        ChartDataModel.Axis xAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Axis yAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Legend legend = ChartDataModel.Legend.builder().build();
        // Sort scan results by build number
        issuesModelList.sort(Comparator.comparing(AstJobMultipleResults.BuildScanBriefDetailed::getBuildNumber));

        List<ChartDataModel.Series> chartSeries = new ArrayList<>();
        // Add "total issues count" series and legend item
        ChartDataModel.Series totalVulnerabilityCountSeries = createTotalIssuesCountSeries(issuesModelList);
        chartSeries.add(totalVulnerabilityCountSeries);
        legend.data.add(totalVulnerabilityCountSeries.getName());

        for (AstJobMultipleResults.BuildScanBriefDetailed buildScanBriefDetailed : issuesModelList)
            // As Jenkins itself prefixes build numbers with "#" sign, let's do the same for chart
            xAxis.getData().add(buildScanBriefDetailed.getBuildNumber().toString());
        for (BaseIssue.Type value : BaseIssue.Type.values()) {
            ChartDataModel.Series valueSeries
                    = ChartDataModel.Series.builder()
                    .name(value.name())
                    .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(TYPE_COLORS.get(value)))
                            .build())
                    .build();
            // Prepare series to fill with data
            for (AstJobMultipleResults.BuildScanBriefDetailed buildScanBriefDetailed : issuesModelList) {
                long count = 0;
                do {
                    ScanBriefDetailed issues = buildScanBriefDetailed.getScanBriefDetailed();
                    if (null == issues) break;
                    if (!Optional.of(issues)
                            .map(ScanBriefDetailed::getDetails)
                            .map(ScanBriefDetailed.Details::getChartData)
                            .map(ScanBriefDetailed.Details.ChartData::getBaseIssueDistributionData).isPresent()) break;
                    count = issues.getDetails().getChartData().getBaseIssueDistributionData().stream()
                            .filter(baseIssue -> value == baseIssue.getClazz())
                            .count();
                } while (false);
                valueSeries.getData().add(ChartDataModel.Series.DataItem.builder().value(count).build());
            }
            // Skip series with no data
            if (valueSeries.getData().stream().noneMatch(i -> i.getValue() != 0)) continue;
            chartSeries.add(valueSeries);
            legend.data.add(value.name());
        }

        ChartDataModel chartDataModel = ChartDataModel.builder()
                .legend(legend)
                .xaxis(Collections.singletonList(xAxis))
                .yaxis(Collections.singletonList(yAxis))
                .series(chartSeries)
                .build();
        return BaseJsonHelper.createObjectMapper().writeValueAsString(chartDataModel);
    }

    @SneakyThrows
    public String getLevelHistoryChart(final int resultsNumber) {
        final List<AstJobMultipleResults.BuildScanBriefDetailed> issuesModelList = getLatestAstResults(resultsNumber);
        // Prepare X-axis
        ChartDataModel.Axis xAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Axis yAxis = ChartDataModel.Axis.builder().build();
        ChartDataModel.Legend legend = ChartDataModel.Legend.builder().build();
        // Sort scan results by build number
        issuesModelList.sort(Comparator.comparing(AstJobMultipleResults.BuildScanBriefDetailed::getBuildNumber));

        List<ChartDataModel.Series> chartSeries = new ArrayList<>();
        // Add "total issues count" series and legend item
        ChartDataModel.Series totalVulnerabilityCountSeries = createTotalIssuesCountSeries(issuesModelList);
        chartSeries.add(totalVulnerabilityCountSeries);
        legend.data.add(totalVulnerabilityCountSeries.getName());

        for (AstJobMultipleResults.BuildScanBriefDetailed buildScanBriefDetailed : issuesModelList)
            // As Jenkins itself prefixes build numbers with "#" sign, let's do the same for chart
            xAxis.getData().add(buildScanBriefDetailed.getBuildNumber().toString());
        for (BaseIssue.Level value : BaseIssue.Level.values()) {
            ChartDataModel.Series valueSeries
                    = ChartDataModel.Series.builder()
                    .name(value.name())
                    .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(LEVEL_COLORS.get(value)))
                            .build())
                    .build();
            // Prepare series to fill with data
            for (AstJobMultipleResults.BuildScanBriefDetailed buildScanBriefDetailed : issuesModelList) {
                long count = 0;
                do {
                    ScanBriefDetailed issues = buildScanBriefDetailed.getScanBriefDetailed();
                    if (null == issues) break;
                    if (!Optional.of(issues)
                            .map(ScanBriefDetailed::getDetails)
                            .map(ScanBriefDetailed.Details::getChartData)
                            .map(ScanBriefDetailed.Details.ChartData::getBaseIssueDistributionData).isPresent()) break;
                    count = issues.getDetails().getChartData().getBaseIssueDistributionData().stream()
                            .filter(baseIssue -> value == baseIssue.getLevel())
                            .count();
                } while (false);
                valueSeries.getData().add(ChartDataModel.Series.DataItem.builder().value(count).build());
            }
            // Skip series with no data
            if (valueSeries.getData().stream().noneMatch(i -> i.getValue() != 0)) continue;
            chartSeries.add(valueSeries);
            legend.data.add(value.name());
        }

        ChartDataModel chartDataModel = ChartDataModel.builder()
                .legend(legend)
                .xaxis(Collections.singletonList(xAxis))
                .yaxis(Collections.singletonList(yAxis))
                .series(chartSeries)
                .build();
        return BaseJsonHelper.createObjectMapper().writeValueAsString(chartDataModel);
    }

    @Override
    public String getIconFileName() {
        return "plugin/" + Objects.requireNonNull(Jenkins.get().getPluginManager().getPlugin("ptai-jenkins-plugin")).getShortName() + "/logo.svg";
    }

    @Override
    public String getDisplayName() {
        return Resources.i18n_ast_result_charts_statistics_label();
    }

    @Override
    public String getUrlName() {
        return "ptai";
    }
}
