package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.ChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import hudson.model.Action;
import hudson.model.Job;
import hudson.model.Run;
import lombok.*;
import lombok.experimental.SuperBuilder;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.util.ArrayList;
import java.util.List;

import static com.ptsecurity.appsec.ai.ee.scan.ScanDataPacked.Type.SCAN_BRIEF_DETAILED;

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

    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    public static class BuildScanBriefDetailed {
        @JsonProperty
        protected Integer buildNumber;
        @JsonProperty
        protected ScanBriefDetailed scanBriefDetailed;
    }

    @NonNull
    protected List<BuildScanBriefDetailed> getLatestAstResults(final int number) {
        final List<? extends Run<?, ?>> builds = project.getBuilds();
        final List<BuildScanBriefDetailed> scanResults = new ArrayList<>();

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

            scanResults.add(BuildScanBriefDetailed.builder()
                    .buildNumber(build.getNumber())
                    .scanBriefDetailed(scanBriefDetailed)
                    .build());
            // Only chart the last N builds (max)
            count++;
            if (count == number) break;
        }
        return scanResults;
    }

    /**
     * Returns the UI model for an ECharts stacked area chart that shows the issues stacked by severity.
     * @return the UI model as JSON
     */
    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getVulnerabilityLevelDistributionChart(final int resultsNumber) {
        final List<BuildScanBriefDetailed> issuesModelList = getLatestAstResults(resultsNumber);
        return BaseJsonChartDataModel.convertObject(ChartDataModel.create(issuesModelList));
    }
}
