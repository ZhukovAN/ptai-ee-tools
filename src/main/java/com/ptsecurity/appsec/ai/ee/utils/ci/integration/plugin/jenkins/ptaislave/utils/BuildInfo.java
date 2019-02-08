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
    private FilePath configDir;
    private TaskListener listener;
    @Setter
    private boolean verbose;
    private String consoleMsgPrefix;
    @Getter
    private BuildEnv currentBuildEnv;
    @Getter
    private BuildEnv targetBuildEnv;

    public BuildInfo(final TaskListener listener, final String consoleMsgPrefix, final FilePath configDir,
                       final BuildEnv currentBuildEnv, final BuildEnv targetBuildEnv) {
        this.listener = listener;
        this.consoleMsgPrefix = consoleMsgPrefix;
        this.configDir = configDir;
        this.currentBuildEnv = currentBuildEnv;
        this.targetBuildEnv = targetBuildEnv;
    }

    public String getRelativePathToFile(final FilePath filePath, final String removePrefix) throws IOException, InterruptedException {
        final String relativePathToFile = getRelativeDir(filePath, removePrefix);
        final int lastDirIdx = relativePathToFile.lastIndexOf('/');
        if (lastDirIdx == -1)
            return "";
        else
            return relativePathToFile.substring(0, lastDirIdx);
    }

    public String getRelativeDir(final FilePath filePath, final String removePrefix) throws IOException, InterruptedException {
        final String normalizedPath = filePath.toURI().normalize().getPath();
        String relativePath = normalizedPath.replace(getNormalizedBaseDirectory(), "");
        if (Util.fixEmptyAndTrim(removePrefix) != null) {
            final String expanded = Util.fixEmptyAndTrim(Util.replaceMacro(removePrefix.trim(), getEnvVars()));
            relativePath = removePrefix(relativePath, expanded);
        }
        return relativePath;
    }

    private String removePrefix(final String relativePathToFile, final String expandedPrefix) {
        if (expandedPrefix == null) return relativePathToFile;
        String toRemove = Util.fixEmptyAndTrim(FilenameUtils.separatorsToUnix(FilenameUtils.normalize(expandedPrefix + "/")));
        if (toRemove != null) {
            if (toRemove.charAt(0) == '/')
                toRemove = toRemove.substring(1);
            if (!relativePathToFile.startsWith(toRemove)) {
                throw new PtaiException(Messages.exception_removePrefix_noMatch(relativePathToFile, toRemove));
            }
            return relativePathToFile.substring(toRemove.length());
        }
        return relativePathToFile;
    }

    public void println(final String message) {
        if (listener != null)
            listener.getLogger().println(consoleMsgPrefix + message);
    }

    public void setEffectiveEnvironmentInBuildInfo() {
        this.setVerbose(verbose);
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
            /*
            this.setBaseDirectory(useWorkspaceInPromotion ? current.getBaseDirectory() : target.getBaseDirectory());
            this.setBuildTime(usePromotionTimestamp ? current.getBuildTime() : target.getBuildTime());
            final TreeMap<String, String> effectiveEnvVars = current.getEnvVarsWithPrefix(BuildInfo.PROMOTION_ENV_VARS_PREFIX);
            effectiveEnvVars.putAll(target.getEnvVars());
            this.setEnvVars(effectiveEnvVars);
            */
        }
    }


}
