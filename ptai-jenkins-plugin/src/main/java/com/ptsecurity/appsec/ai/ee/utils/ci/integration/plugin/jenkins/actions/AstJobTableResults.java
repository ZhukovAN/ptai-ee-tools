package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions;

import hudson.model.Action;
import hudson.model.Job;
import hudson.model.Run;
import jenkins.model.Jenkins;
import jenkins.model.RunAction2;
import jenkins.tasks.SimpleBuildStep;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class AstJobTableResults implements Action {
    @Getter
    @NonNull
    protected String projectName;

    public Job<?, ?> getProject() {
        List<Job> allProjects = Jenkins.get().getAllItems(Job.class);
        for (Job next : allProjects) {
            if (null != next && projectName.equals(next.getFullName()))
                return next;
        }
        return null;
    }

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
        return "ptai-issues";
    }
}
