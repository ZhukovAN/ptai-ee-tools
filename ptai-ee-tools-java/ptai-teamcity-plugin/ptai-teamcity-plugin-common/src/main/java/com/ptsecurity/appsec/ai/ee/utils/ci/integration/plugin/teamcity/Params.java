package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.PREFIX;

public class Params {
    // Globally defined parameter names
    public static final String GLOBAL_URL = PARAM("GlobalUrl");
    public static final String GLOBAL_USER = PARAM("GlobalUser");
    public static final String GLOBAL_TOKEN = PARAM("GlobalToken");
    public static final String GLOBAL_TRUSTED_CERTIFICATES = PARAM("GlobalTrustedCertificates");

    // Task-scope defined parameter names
    /**
     * Field that stores scan settings type: UI- or JSON-based
     */
    public static final String SCAN_SETTINGS = PARAM("ScanSettings");
    public static final String PROJECT_NAME = PARAM("ProjectName");
    public static final String JSON_SETTINGS = PARAM("JsonSettings");
    public static final String JSON_POLICY = PARAM("JsonPolicy");
    public static final String FAIL_IF_FAILED = PARAM("FailIfFailed");
    public static final String FAIL_IF_UNSTABLE = PARAM("FailIfUnstable");
    public static final String NODE_NAME = PARAM("NodeName");
    public static final String VERBOSE = "Verbose";
    public static final String INCLUDES = PARAM("Includes");
    public static final String REMOVE_PREFIX = PARAM("RemovePrefix");
    public static final String EXCLUDES = PARAM("Excludes");
    public static final String PATTERN_SEPARATOR = PARAM("PatternSeparator");
    public static final String USE_DEFAULT_EXCLUDES = PARAM("UseDefaultExcludes");
    public static final String FLATTEN = PARAM("Flatten");

    private static String PARAM(final String field) {
        return PREFIX + field;
    }
}
