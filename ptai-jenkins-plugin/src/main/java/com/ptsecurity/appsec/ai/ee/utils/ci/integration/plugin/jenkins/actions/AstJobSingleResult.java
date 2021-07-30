package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.StackedAreaChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.report.chart.model.VulnerabilityLevelBar;
import hudson.model.Run;
import jenkins.model.Jenkins;
import jenkins.model.RunAction2;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import net.sf.json.JSONObject;
import org.apache.commons.lang.WordUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
    protected ScanResult scanResult;

    @Override
    public void onAttached(Run<?, ?> r) {
        this.run = r;
    }

    @Override
    public void onLoad(Run<?, ?> r) {
        this.run = r;
    }

    @Getter
    @RequiredArgsConstructor
    protected static class Couple {
        protected final BaseIssue.Level level;
        protected final Long count;
    }

    @Getter
    @RequiredArgsConstructor
    protected static class Triple {
        protected final BaseIssue.Level level;
        protected final String title;
        protected final Long count;
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getScanBrief() {
        ScanBrief res = scanResult;
        return BaseJsonChartDataModel.convertObject(res);
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getSeverityDistributionBar() {
        Map<BaseIssue.Level, Long> distribution = scanResult.getIssues().stream()
                .collect(Collectors.groupingBy(
                        BaseIssue::getLevel,
                        Collectors.counting()));
        Comparator<Couple> compareLevelAndCount = Comparator
                .comparing(Couple::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue).reversed())
                .thenComparing(Couple::getCount, Comparator.reverseOrder());
        //.thenComparing(Triple::getCount).reversed();
        List<Couple> distributionList = new ArrayList<>();

        for (BaseIssue.Level key : distribution.keySet())
            distributionList.add(new Couple(key, distribution.get(key)));

        VulnerabilityLevelBar.Series series = VulnerabilityLevelBar.Series.builder().type("bar").build();
        VulnerabilityLevelBar bar = VulnerabilityLevelBar.builder().build();
        bar.getSeries().add(series);

        distributionList.stream().sorted(compareLevelAndCount).forEach(t -> {
            bar.getYaxis().getData().add(WordUtils.capitalize(t.level.name().toLowerCase()));
            series.getData().add(VulnerabilityLevelBar.DataItem.builder()
                    .value(t.count)
                    .itemStyle(VulnerabilityLevelBar.ITEM_STYLE_MAP.get(t.level))
                    .build());
        });
        return BaseJsonChartDataModel.convertObject(bar);
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getTypeDistributionBar() {
        Map<Pair<BaseIssue.Level, String>, Long> distribution = scanResult.getIssues().stream()
                .collect(Collectors.groupingBy(
                        issue -> new ImmutablePair<>(issue.getLevel(), issue.getTitle()),
                        Collectors.counting()));
        Comparator<Triple> compareLevelAndCount = Comparator
                .comparing(Triple::getLevel, Comparator.comparingInt(BaseIssue.Level::getValue).reversed())
                .thenComparing(Triple::getCount, Comparator.reverseOrder());
        //.thenComparing(Triple::getCount).reversed();
        List<Triple> distributionList = new ArrayList<>();

        for (Pair<BaseIssue.Level, String> key : distribution.keySet())
            distributionList.add(new Triple(key.getLeft(), key.getRight(), distribution.get(key)));

        VulnerabilityLevelBar.Series series = VulnerabilityLevelBar.Series.builder().type("bar").build();
        VulnerabilityLevelBar bar = VulnerabilityLevelBar.builder().build();
        bar.getSeries().add(series);

        distributionList.stream().sorted(compareLevelAndCount).forEach(t -> {
            bar.getYaxis().getData().add(t.title);
            series.getData().add(VulnerabilityLevelBar.DataItem.builder()
                    .value(t.count)
                    .itemStyle(VulnerabilityLevelBar.ITEM_STYLE_MAP.get(t.level))
                    .build());
        });
        return BaseJsonChartDataModel.convertObject(bar);
    }
}
