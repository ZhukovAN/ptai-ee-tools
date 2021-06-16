package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.IssuesModel;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.StackedAreaChartDataModel;
import hudson.model.Action;
import hudson.model.Run;
import jenkins.model.RunAction2;
import jenkins.tasks.SimpleBuildStep;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@RequiredArgsConstructor
public class AstJobSingleResult implements RunAction2 {
    @NonNull
    @Getter
    private transient Run run;

    @Override
    public String getIconFileName() {
        return "document.png";
    }

    @Override
    public String getDisplayName() {
        return "PT AI single assessment";
    }

    @Override
    public String getUrlName() {
        return "ptai";
    }

    @Getter
    @Setter
    protected IssuesModel issues;

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
}
