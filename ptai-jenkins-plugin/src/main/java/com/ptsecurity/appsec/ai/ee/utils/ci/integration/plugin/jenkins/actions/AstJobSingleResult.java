package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.report.chart.model.VulnerabilityLevelBar;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanDataPacked;
import hudson.model.Run;
import jenkins.model.Jenkins;
import jenkins.model.RunAction2;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import net.sf.json.JSONObject;
import org.apache.commons.lang.WordUtils;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import static com.ptsecurity.appsec.ai.ee.scan.ScanDataPacked.Type.SCAN_BRIEF_DETAILED;

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

    public ScanBriefDetailed getScanBriefDetailed() {
        if (null == scanDataPacked) return null;
        if (SCAN_BRIEF_DETAILED != scanDataPacked.getType()) return null;
        return scanDataPacked.unpackData(ScanBriefDetailed.class);
    }

    @JavaScriptMethod
    @SuppressWarnings("unused") // Called by groovy view
    public JSONObject getScanBriefDetailedJson() {
        return BaseJsonChartDataModel.convertObject(getScanBriefDetailed());
    }
}
