package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

/**
 * Class contains constants that are used as a labels in UI
 */
public class Labels {
    public static final String PLUGIN_TAB_TITLE = "PT AI";
    public static final String RUNNER = PLUGIN_TAB_TITLE;
    public static final String TEST  = "Test PT AI server connection";

    // Administrative settings labels
    public static final String GLOBAL_URL = "PT AI server URL";
    public static final String GLOBAL_USER = "PT AI user name";
    public static final String GLOBAL_TOKEN = "PT AI API token";
    public static final String GLOBAL_TRUSTED_CERTIFICATES = "PT AI server trusted certificates";

    // Task settings labels
    public static final String SCAN_SETTINGS = "Scan settings type";
    public static final String PROJECT_NAME = "Project name";
    public static final String JSON_SETTINGS = "Scans settings";
    public static final String JSON_POLICY = "Policy";
    public static final String FAIL_IF_FAILED = "Fail step if SAST failed";
    public static final String FAIL_IF_UNSTABLE = "Fail step if SAST unstable";
    public static final String NODE_NAME = "AST agent node name";
    public static final String VERBOSE = "Verbose logging";
    public static final String INCLUDES = "Files to analyse";
    public static final String REMOVE_PREFIX = "Remove prefix";
    public static final String EXCLUDES = "Exclude files";
    public static final String PATTERN_SEPARATOR = "Pattern separator";
    public static final String USE_DEFAULT_EXCLUDES = "Use default excludes";
    public static final String FLATTEN = "Flatten files";

    public static final String SETTINGS_JSON = "JSON-defined settings";
    public static final String SETTINGS_UI = "PT AI viewer-defined settings";

    public static final String CONFIG_GLOBAL = "Global scope defined PT AI server config";
    public static final String CONFIG_TASK = "Task scope defined PT AI server config";

    public static final String STEP_FAIL_CONDITIONS = "Build step fail conditions";
}
