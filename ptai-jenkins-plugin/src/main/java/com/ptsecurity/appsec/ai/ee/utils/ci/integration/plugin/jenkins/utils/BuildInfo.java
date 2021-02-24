package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import lombok.Getter;

import java.util.TreeMap;

public class BuildInfo extends BuildEnv {
    @Getter
    private final BuildEnv currentBuildEnv;

    @Getter
    private final BuildEnv targetBuildEnv;

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
