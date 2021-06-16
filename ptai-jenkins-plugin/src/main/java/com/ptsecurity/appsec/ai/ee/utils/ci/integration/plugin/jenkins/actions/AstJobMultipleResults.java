package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.IssuesModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.StackedAreaChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel;
import hudson.model.Action;
import hudson.model.Job;
import hudson.model.Run;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Triple;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
    public List<Triple<Integer, LocalDateTime, IssuesModel>> getLatestAstResults(final int number) {
        final List<? extends Run<?, ?>> builds = project.getBuilds();
        final List<Triple<Integer, LocalDateTime, IssuesModel>> issuesModelList = new ArrayList<>();

        int count = 0;
        for (Run<?, ?> build : builds) {
            final AstJobSingleResult action = build.getAction(AstJobSingleResult.class);
            if (null == action) continue;
            if (null == action.getScanResult()) continue;
            if (null == action.getIssues()) continue;

            LocalDateTime dateTime = LocalDateTime.parse(action.getScanResult().getScanDate(), DateTimeFormatter.ISO_DATE_TIME);
            issuesModelList.add(new ImmutableTriple<>(build.getNumber(), dateTime, action.getIssues()));
            // Only chart the last N builds (max)
            count++;
            if (count == number) break;
        }
        return issuesModelList;
    }

    @SuppressWarnings("unused") // Called by jelly view
    public boolean resultsAvailable() {
        final List<Triple<Integer, LocalDateTime, IssuesModel>> issuesModelList = getLatestAstResults(1);
        return !issuesModelList.isEmpty();
    }

    /**
     * Returns the UI model for an ECharts stacked area chart that shows the issues stacked by severity.
     * @return the UI model as JSON
     */
    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by jelly view
    public JSONObject getSeverityDistributionTrend() {
        final List<Triple<Integer, LocalDateTime, IssuesModel>> issuesModelList = getLatestAstResults(10);
        StackedAreaChartDataModel model = StackedAreaChartDataModel.create(issuesModelList);
        return BaseJsonChartDataModel.convertObject(model);
    }
}
