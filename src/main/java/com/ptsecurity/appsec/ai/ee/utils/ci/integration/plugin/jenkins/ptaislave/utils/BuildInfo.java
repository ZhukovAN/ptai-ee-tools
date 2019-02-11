package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.exceptions.PtaiException;
import hudson.FilePath;
import hudson.Util;
import hudson.model.TaskListener;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.io.FilenameUtils;

import java.io.IOException;
import java.util.Calendar;
import java.util.TreeMap;

public class BuildInfo extends BuildEnv {
    @Getter
    private BuildEnv currentBuildEnv;

    @Getter
    private BuildEnv targetBuildEnv;

    public BuildInfo(final BuildEnv currentBuildEnv, final BuildEnv targetBuildEnv) {
        this.currentBuildEnv = currentBuildEnv;
        this.targetBuildEnv = targetBuildEnv;
    }

    public void setEffectiveEnvironmentInBuildInfo() {
        final BuildEnv current = this.getCurrentBuildEnv();
        final BuildEnv target = this.getTargetBuildEnv();
        if (target == null) {
            this.setEnvVars(current.getEnvVars());
            this.setBaseDirectory(current.getBaseDirectory());
            this.setBuildTime(current.getBuildTime());
        } else {
            this.setBaseDirectory(target.getBaseDirectory());
            this.setBuildTime(target.getBuildTime());
            final TreeMap<String, String> effectiveEnvVars = current.getEnvVars();
            effectiveEnvVars.putAll(target.getEnvVars());
            this.setEnvVars(effectiveEnvVars);
        }
    }
}
