package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
import org.jetbrains.annotations.NotNull;

/**
 * Bean stores all settings that may be set for a PT AI build step. Global
 * settings aren't part of this bean as those are injected separately
 * with BuildStartContextProcessor (as a build job parameters) and
 * a AstEditRunTypeControllerExtension (as a build step settings)
 */
public class AstOptionsBean {
    @NotNull
    public String getPtaiScanSettings() {
        return Params.SCAN_SETTINGS;
    }

    /**
     * @return PT AI project name as it seen in the PT AI EE Viewer
     */
    @NotNull
    public String getPtaiProjectName() {
        return Params.PROJECT_NAME;
    }

    @NotNull
    public String getPtaiJsonSettings() {
        return Params.JSON_SETTINGS;
    }

    @NotNull
    public String getPtaiJsonPolicy() {
        return Params.JSON_POLICY;
    }

    @NotNull
    public String getPtaiFailIfFailed() {
        return Params.FAIL_IF_FAILED;
    }

    @NotNull
    public String getPtaiFailIfUnstable() {
        return Params.FAIL_IF_UNSTABLE;
    }

    @NotNull
    public String getPtaiNodeName() {
        return Params.NODE_NAME;
    }

    @NotNull
    public String getPtaiVerbose() {
        return Params.VERBOSE;
    }

    @NotNull
    public String getPtaiIncludes() {
        return Params.INCLUDES;
    }

    @NotNull
    public String getPtaiRemovePrefix() {
        return Params.REMOVE_PREFIX;
    }

    @NotNull
    public String getPtaiExcludes() {
        return Params.EXCLUDES;
    }

    @NotNull
    public String getPtaiPatternSeparator() {
        return Params.PATTERN_SEPARATOR;
    }

    @NotNull
    public String getPtaiUseDefaultExcludes() {
        return Params.USE_DEFAULT_EXCLUDES;
    }

    @NotNull
    public String getPtaiFlatten() {
        return Params.FLATTEN;
    }
}
