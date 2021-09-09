package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed.Details.ChartData.BaseIssueCount;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.ChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.PieChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.TreeChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.BaseReport;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import hudson.model.Action;
import hudson.model.Run;
import jenkins.model.Jenkins;
import jenkins.model.RunAction2;
import jenkins.tasks.SimpleBuildStep;
import lombok.*;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.scan.ScanDataPacked.Type.SCAN_BRIEF_DETAILED;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel.*;

@RequiredArgsConstructor
public class AstJobSingleResult implements RunAction2, SimpleBuildStep.LastBuildAction {
    @NonNull
    @Getter
    private transient Run run;

    @Override
    public String getIconFileName() {
        return Plugin.getPluginUrl() + "/icons/logo.svg";
    }

    public String getLogo48() {
        return Plugin.getPluginUrl() + "/icons/logo.48x48.svg";
    }

    @Override
    public String getDisplayName() {
        return Resources.i18n_ast_result_charts_scan_label();
    }

    @Override
    public String getUrlName() {
        return "ptai";
    }

    @Getter
    @Setter
    protected ScanDataPacked scanDataPacked;

    protected transient ScanBriefDetailed scanBriefDetailed = null;

    public ScanBriefDetailed getScanBriefDetailed() {
        if (null != scanBriefDetailed) return scanBriefDetailed;

        if (null == scanDataPacked) return null;
        if (SCAN_BRIEF_DETAILED != scanDataPacked.getType()) return null;
        scanBriefDetailed = scanDataPacked.unpackData(ScanBriefDetailed.class);

        Reports.Locale locale = BaseReport.BaseReportDescriptor.getDefaultLocale();
        Comparator<ScanBriefDetailed.Details.ChartData.BaseIssueCount> compareLevelTypeAndCount = Comparator
                .comparing(ScanBriefDetailed.Details.ChartData.BaseIssueCount::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue).reversed())
                .thenComparing(ScanBriefDetailed.Details.ChartData.BaseIssueCount::getCount, Comparator.reverseOrder())
                .thenComparing(brief -> brief.getTitle().get(locale), Comparator.reverseOrder());
        return scanBriefDetailed;
    }

    @Override
    public void onAttached(Run<?, ?> r) {
        this.run = r;
    }

    @Override
    public void onLoad(Run<?, ?> r) {
        this.run = r;
    }

    @Getter
    @Builder
    @RequiredArgsConstructor
    protected static class Couple {
        protected final BaseIssue.Level level;
        protected final Long count;
    }

    @Getter
    @Builder
    @RequiredArgsConstructor
    protected static class Triple {
        protected final BaseIssue.Level level;
        protected final String title;
        protected final Long count;
    }

    public boolean isEmpty() {
        getScanBriefDetailed();
        return Optional.ofNullable(scanBriefDetailed)
                .map(ScanBriefDetailed::getDetails)
                .map(ScanBriefDetailed.Details::getChartData)
                .map(ScanBriefDetailed.Details.ChartData::getBaseIssueDistributionData)
                .map(List::isEmpty).orElse(true);
    }

    @SneakyThrows
    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityLevelDistribution() {
        getScanBriefDetailed();
        if (isEmpty()) return null;

        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();
        Map<BaseIssue.Level, Long> levelCountMap = baseIssues.stream()
                .filter(issue -> BaseIssue.ApprovalState.DISCARD != issue.getApprovalState())
                .collect(Collectors.groupingBy(
                        BaseIssueCount::getLevel,
                        Collectors.counting()));
        ChartDataModel dataModel = ChartDataModel.builder()
                .xaxis(Collections.singletonList(ChartDataModel.Axis.builder().build()))
                .yaxis(Collections.singletonList(ChartDataModel.Axis.builder().build()))
                .series(Collections.singletonList(ChartDataModel.Series.builder().build()))
                .build();
        List<Couple> levelCount = new ArrayList<>();
        levelCountMap.forEach((k, v) -> levelCount.add(Couple.builder().level(k).count(v).build()));
        Comparator<Couple> c = Comparator
                .comparing(Couple::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue));
        levelCount.stream().sorted(c).forEach(t -> {
            dataModel.getYaxis().get(0).getData().add(t.level.name());
            dataModel.getSeries().get(0).getData().add(ChartDataModel.Series.DataItem.builder()
                    .value(levelCountMap.get(t.level))
                    .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(LEVEL_COLORS.get(t.level)))
                            .build())
                    .build());
        });
        return BaseJsonHelper.createObjectMapper().writeValueAsString(dataModel);
    }

    @SneakyThrows
    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityTypeDistribution() {
        getScanBriefDetailed();
        if (isEmpty()) return null;
        Reports.Locale locale = BaseReport.BaseReportDescriptor.getDefaultLocale();
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();
        Map<Pair<BaseIssue.Level, String>, Long> levelTitleCountMap = baseIssues.stream()
                .filter(issue -> BaseIssue.ApprovalState.DISCARD != issue.getApprovalState())
                .collect(Collectors.groupingBy(
                        issue -> new ImmutablePair<>(issue.getLevel(), issue.getTitle().get(locale)),
                        Collectors.counting()));
        List<Triple> levelTitleCount = new ArrayList<>();
        levelTitleCountMap.forEach((k, v) -> levelTitleCount.add(Triple.builder()
                .level(k.getLeft())
                .title(k.getRight())
                .count(v)
                .build()));
        Comparator<Triple> c = Comparator
                .comparing(Triple::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue))
                .thenComparing(Triple::getCount)
                .thenComparing(Triple::getTitle, Comparator.reverseOrder());

        ChartDataModel dataModel = ChartDataModel.builder()
                .xaxis(Collections.singletonList(ChartDataModel.Axis.builder().build()))
                .yaxis(Collections.singletonList(ChartDataModel.Axis.builder().build()))
                .series(Collections.singletonList(ChartDataModel.Series.builder().build()))
                .build();
        levelTitleCount.stream().sorted(c).forEach(t -> {
            dataModel.getYaxis().get(0).getData().add(t.getTitle());
            dataModel.getSeries().get(0).getData().add(ChartDataModel.Series.DataItem.builder()
                    .value(t.getCount())
                    .itemStyle(ChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(LEVEL_COLORS.get(t.getLevel())))
                            .build())
                    .build());
        });
        return BaseJsonHelper.createObjectMapper().writeValueAsString(dataModel);
    }

    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityTypePie() throws JsonProcessingException {
        getScanBriefDetailed();
        if (isEmpty()) return null;
        PieChartDataModel dataModel = PieChartDataModel.builder()
                .series(Collections.singletonList(PieChartDataModel.Series.builder().build()))
                .build();
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();

        for (BaseIssue.Type type : BaseIssue.Type.values()) {
            long count = baseIssues.stream()
                    .filter(issue -> type == issue.getClazz()).count();
            if (0 == count) continue;
            PieChartDataModel.Series.DataItem typeItem = PieChartDataModel.Series.DataItem.builder()
                    .name(type.name())
                    .itemStyle(PieChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(TYPE_COLORS.get(type)))
                            .build())
                    .value(count)
                    .build();
            dataModel.getSeries().get(0).getData().add(typeItem);
        }
        return BaseJsonHelper.createObjectMapper().writeValueAsString(dataModel);
    }

    @SneakyThrows
    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityApprovalStatePie() {
        getScanBriefDetailed();
        if (isEmpty()) return null;
        PieChartDataModel dataModel = PieChartDataModel.builder()
                .series(Collections.singletonList(PieChartDataModel.Series.builder().build()))
                .build();
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();

        for (BaseIssue.ApprovalState approvalState : BaseIssue.ApprovalState.values()) {
            long count = baseIssues.stream()
                    .filter(issue -> approvalState == issue.getApprovalState()).count();
            if (0 == count) continue;
            PieChartDataModel.Series.DataItem typeItem = PieChartDataModel.Series.DataItem.builder()
                    .name(approvalState.name())
                    .itemStyle(PieChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(APPROVAL_COLORS.get(approvalState)))
                            .build())
                    .value(count)
                    .build();
            dataModel.getSeries().get(0).getData().add(typeItem);
        }
        return BaseJsonHelper.createObjectMapper().writeValueAsString(dataModel);
    }

    @SneakyThrows
    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilitySuspectedPie() {
        getScanBriefDetailed();
        if (isEmpty()) return null;
        PieChartDataModel dataModel = PieChartDataModel.builder()
                .series(Collections.singletonList(PieChartDataModel.Series.builder().build()))
                .build();
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();

        for (Boolean suspected : new HashSet<>(Arrays.asList(true, false))) {
            long count = baseIssues.stream()
                    .filter(issue -> suspected == issue.getSuspected()).count();
            if (0 == count) continue;
            PieChartDataModel.Series.DataItem typeItem = PieChartDataModel.Series.DataItem.builder()
                    .name(suspected.toString())
                    .itemStyle(PieChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(SUSPECTED_COLORS.get(suspected)))
                            .build())
                    .value(count)
                    .build();
            dataModel.getSeries().get(0).getData().add(typeItem);
        }
        return BaseJsonHelper.createObjectMapper().writeValueAsString(dataModel);
    }

    @SneakyThrows
    @SuppressWarnings("unused") // Called by groovy view
    public String getVulnerabilityScanModePie() {
        getScanBriefDetailed();
        if (isEmpty()) return null;
        PieChartDataModel dataModel = PieChartDataModel.builder()
                .series(Collections.singletonList(PieChartDataModel.Series.builder().build()))
                .build();
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();

        for (VulnerabilityIssue.ScanMode scanMode : VulnerabilityIssue.ScanMode.values()) {
            long count = baseIssues.stream()
                    .filter(issue -> scanMode == issue.getScanMode()).count();
            if (0 == count) continue;
            PieChartDataModel.Series.DataItem typeItem = PieChartDataModel.Series.DataItem.builder()
                    .name(scanMode.toString())
                    .itemStyle(PieChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(SCANMODE_COLORS.get(scanMode)))
                            .build())
                    .value(count)
                    .build();
            dataModel.getSeries().get(0).getData().add(typeItem);
        }
        return BaseJsonHelper.createObjectMapper().writeValueAsString(dataModel);
    }

    @Override
    public Collection<? extends Action> getProjectActions() {
        List<Action> projectActions = new ArrayList<>();
        projectActions.add(new AstJobMultipleResults(run.getParent()));
        projectActions.add(new AstJobTableResults(run.getParent()));
        return projectActions;
    }
}
