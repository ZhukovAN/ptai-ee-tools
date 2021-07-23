package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import hudson.model.Run;
import jenkins.model.RunAction2;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@RequiredArgsConstructor
public class AstJobSingleResult implements RunAction2 {
    @NonNull
    @Getter
    private transient Run run;

    @Override
    public String getIconFileName() {
        // TODO: Implement project actions and uncomment this
        // return "plugin/" + Jenkins.get().getPluginManager().getPlugin("ptai-jenkins-plugin").getShortName() + "/24x24.png";
        return null;
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
}
