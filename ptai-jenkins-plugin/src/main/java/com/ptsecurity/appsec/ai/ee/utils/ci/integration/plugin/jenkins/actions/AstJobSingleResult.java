package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed.Details.ChartData.BaseIssueCount;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.ChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.PieChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.TreeChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import hudson.model.Run;
import jenkins.model.Jenkins;
import jenkins.model.RunAction2;
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
public class AstJobSingleResult implements RunAction2 {
    @NonNull
    @Getter
    private transient Run run;

    @Override
    public String getIconFileName() {
        // TODO: Implement project actions and uncomment this
        return "plugin/" + Jenkins.get().getPluginManager().getPlugin("ptai-jenkins-plugin").getShortName() + "/24x24.png";
    }

    @Override
    public String getDisplayName() {
        return "PT AI";
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
        return scanBriefDetailed;
    }

    protected transient JSONObject scanBriefDetailedJson = null;

    protected transient JSONObject vulnerabilityTypeDistribution = null;
    protected transient JSONObject vulnerabilityLevelDistribution = null;
    protected transient JSONObject vulnerabilitySunBurst = null;

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
        return (null == scanBriefDetailed) || scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData().isEmpty();
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilityLevelDistribution() {
        if (null != vulnerabilityLevelDistribution)
            return vulnerabilityLevelDistribution;
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
        vulnerabilityLevelDistribution = BaseJsonChartDataModel.convertObject(dataModel);
        return vulnerabilityLevelDistribution;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilityTypeDistribution() {
        if (null != vulnerabilityTypeDistribution)
            return vulnerabilityTypeDistribution;
        if (isEmpty()) return null;
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();
        Map<Pair<BaseIssue.Level, String>, Long> levelTitleCountMap = baseIssues.stream()
                .filter(issue -> BaseIssue.ApprovalState.DISCARD != issue.getApprovalState())
                .collect(Collectors.groupingBy(
                        issue -> new ImmutablePair<>(issue.getLevel(), issue.getTitle()),
                        Collectors.counting()));
        List<Triple> levelTitleCount = new ArrayList<>();
        levelTitleCountMap.forEach((k, v) -> levelTitleCount.add(Triple.builder()
                .level(k.getLeft())
                .title(k.getRight())
                .count(v)
                .build()));
        Comparator<Triple> c = Comparator
                .comparing(Triple::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue))
                .thenComparing(Triple::getCount);

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
        vulnerabilityTypeDistribution = BaseJsonChartDataModel.convertObject(dataModel);
        return vulnerabilityTypeDistribution;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilitySunBurst() {
        if (null != vulnerabilitySunBurst)
            return vulnerabilitySunBurst;
        if (isEmpty()) return null;
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();
        Map<BaseIssue.Level, Long> levelCountMap = baseIssues.stream()
                .filter(issue -> BaseIssue.ApprovalState.DISCARD != issue.getApprovalState())
                .collect(Collectors.groupingBy(
                        BaseIssueCount::getLevel,
                        Collectors.counting()));
        TreeChartDataModel dataModel = TreeChartDataModel.builder()
                .series(Collections.singletonList(TreeChartDataModel.Series.builder().build()))
                .build();
        List<Couple> levelCount = new ArrayList<>();
        levelCountMap.forEach((k, v) -> levelCount.add(Couple.builder().level(k).count(v).build()));
        Comparator<Couple> c = Comparator
                .comparing(Couple::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue));
        levelCount.stream().sorted(c).forEach(t -> {
            dataModel.getSeries().get(0).getData().add(TreeChartDataModel.Series.DataItem.builder()
                    .value(levelCountMap.get(t.level))
                    .name(t.level.name())
                    .itemStyle(TreeChartDataModel.Series.DataItem.ItemStyle.builder()
                            .color("#" + Integer.toHexString(LEVEL_COLORS.get(t.level)))
                            .build())
                    .build());
        });
        vulnerabilitySunBurst = BaseJsonChartDataModel.convertObject(dataModel);
        return vulnerabilitySunBurst;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilitySunBurstA() {
        // if (null != vulnerabilitySunBurst)
        //     return vulnerabilitySunBurst;
        if (isEmpty()) return null;
        TreeChartDataModel dataModel = TreeChartDataModel.builder()
                .series(Collections.singletonList(TreeChartDataModel.Series.builder().build()))
                .build();
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();
        for (BaseIssue.ApprovalState approvalState : BaseIssue.ApprovalState.values()) {
            TreeChartDataModel.Series.DataItem approvalStateItem = TreeChartDataModel.Series.DataItem.builder()
                    .name(approvalState.name())
                    .build();
            dataModel.getSeries().get(0).getData().add(approvalStateItem);
            for (BaseIssue.Level level : BaseIssue.Level.values()) {
                long count = baseIssues.stream()
                        .filter(issue -> approvalState == issue.getApprovalState())
                        .filter(issue -> level == issue.getLevel()).count();
                TreeChartDataModel.Series.DataItem levelItem = TreeChartDataModel.Series.DataItem.builder()
                        .name(level.name())
                        .value(count)
                        .itemStyle(TreeChartDataModel.Series.DataItem.ItemStyle.builder()
                                .color("#" + Integer.toHexString(LEVEL_COLORS.get(level)))
                                .build())
                        .build();
                approvalStateItem.getChildren().add(levelItem);
            }
        }
        /* vulnerabilitySunBurst = */ return BaseJsonChartDataModel.convertObject(dataModel);
        // return vulnerabilitySunBurst;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilitySunBurstB() {
        // if (null != vulnerabilitySunBurst)
        //     return vulnerabilitySunBurst;
        if (isEmpty()) return null;
        TreeChartDataModel dataModel = TreeChartDataModel.builder()
                .series(Collections.singletonList(TreeChartDataModel.Series.builder().build()))
                .build();
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();
        for (BaseIssue.Type type : BaseIssue.Type.values()) {
            TreeChartDataModel.Series.DataItem typeItem = TreeChartDataModel.Series.DataItem.builder()
                    .name(type.name())
                    .build();
            dataModel.getSeries().get(0).getData().add(typeItem);
            for (Boolean suspected : new HashSet<Boolean>(Arrays.asList(true, false))) {
                long count = baseIssues.stream()
                        .filter(issue -> suspected == issue.getSuspected())
                        .filter(issue -> type == issue.getClazz()).count();
                TreeChartDataModel.Series.DataItem suspectedItem = TreeChartDataModel.Series.DataItem.builder()
                        .name(suspected.toString())
                        .value(count)
                        .itemStyle(TreeChartDataModel.Series.DataItem.ItemStyle.builder()
                                // .color("#" + Integer.toHexString(COLORS.get(level)))
                                .build())
                        .build();
                typeItem.getChildren().add(suspectedItem);
            }
        }
        /* vulnerabilitySunBurst = */ return BaseJsonChartDataModel.convertObject(dataModel);
        // return vulnerabilitySunBurst;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilityTypePie() {
        // if (null != vulnerabilitySunBurst)
        //     return vulnerabilitySunBurst;
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
        /* vulnerabilitySunBurst = */ return BaseJsonChartDataModel.convertObject(dataModel);
        // return vulnerabilitySunBurst;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilityApprovalStatePie() {
        // if (null != vulnerabilitySunBurst)
        //     return vulnerabilitySunBurst;
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
        /* vulnerabilitySunBurst = */ return BaseJsonChartDataModel.convertObject(dataModel);
        // return vulnerabilitySunBurst;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilitySuspectedPie() {
        // if (null != vulnerabilitySunBurst)
        //     return vulnerabilitySunBurst;
        if (isEmpty()) return null;
        PieChartDataModel dataModel = PieChartDataModel.builder()
                .series(Collections.singletonList(PieChartDataModel.Series.builder().build()))
                .build();
        List<BaseIssueCount> baseIssues = scanBriefDetailed.getDetails().getChartData().getBaseIssueDistributionData();

        for (Boolean suspected : new HashSet<Boolean>(Arrays.asList(true, false))) {
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
        /* vulnerabilitySunBurst = */ return BaseJsonChartDataModel.convertObject(dataModel);
        // return vulnerabilitySunBurst;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilityScanModePie() {
        // if (null != vulnerabilitySunBurst)
        //     return vulnerabilitySunBurst;
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
        /* vulnerabilitySunBurst = */ return BaseJsonChartDataModel.convertObject(dataModel);
        // return vulnerabilitySunBurst;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getScanBriefDetailedJson() {
        if (null == scanBriefDetailedJson)
            scanBriefDetailedJson = BaseJsonChartDataModel.convertObject(getScanBriefDetailed());
        return scanBriefDetailedJson;
    }
}
