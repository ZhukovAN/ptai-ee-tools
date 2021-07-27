package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.StackedAreaChartDataModel;
import hudson.model.Action;
import hudson.model.Job;
import hudson.model.Run;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.util.ArrayList;
import java.util.List;

/**
 * Class implements project-scope basic chart generation that is shown at project page
 */
@RequiredArgsConstructor
public class AstJobMultipleResults implements Action {
    @NonNull
    private final Job<?, ?> project;

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return "ptaiTrend";
    }

    public String getChartCaption() {
        return Resources.i18n_ast_result_charts_trend_caption();
    }

    @NonNull
    public List<Pair<Integer, ScanResult>> getLatestAstResults(final int number) {
        final List<? extends Run<?, ?>> builds = project.getBuilds();
        final List<Pair<Integer, ScanResult>> scanResults = new ArrayList<>();

        int count = 0;
        for (Run<?, ?> build : builds) {
            final AstJobSingleResult action = build.getAction(AstJobSingleResult.class);
            if (null == action) continue;
            if (null == action.getScanResult()) continue;

            scanResults.add(new ImmutablePair<>(build.getNumber(), action.getScanResult()));
            // Only chart the last N builds (max)
            count++;
            if (count == number) break;
        }
        return scanResults;
    }

    @SuppressWarnings("unused") // Called by groovy view
    public boolean resultsAvailable() {
        final List<Pair<Integer, ScanResult>> issuesModelList = getLatestAstResults(1);
        return !issuesModelList.isEmpty();
    }

    /**
     * Returns the UI model for an ECharts stacked area chart that shows the issues stacked by severity.
     * @return the UI model as JSON
     */
    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getSeverityDistributionTrend() {
        final List<Pair<Integer, ScanResult>> issuesModelList = getLatestAstResults(10);
        StackedAreaChartDataModel model = StackedAreaChartDataModel.create(issuesModelList);
        return BaseJsonChartDataModel.convertObject(model);
    }
}
