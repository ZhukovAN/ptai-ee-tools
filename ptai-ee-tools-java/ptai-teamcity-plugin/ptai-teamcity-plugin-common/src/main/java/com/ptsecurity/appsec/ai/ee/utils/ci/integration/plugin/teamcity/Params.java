package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.PREFIX;

/**
 * Parameter names that are used in plugin settings
 */
public class Params {
    // PT AI connection parameter names
    public static final String URL = PARAM("Url");
    public static final String TOKEN = PARAM("Token");
    public static final String CERTIFICATES = PARAM("Certificates");

    /**
     * Field that stores scan settings type: UI- or JSON-based. If this
     * field equals to Constants.SERVER_SETTINGS_GLOBAL then globally defined PT AI
     * server connection settings will be used
     * (see URL..CERTIFICATES). If equals to
     * Constants.CONFIG_LOCAL then PT AI server connection settings are
     * defined as a build step parameters
     */
    public static final String SERVER_SETTINGS = PARAM("ServerSettings");

    /**
     * Defines how code AST settings are defined. If this field equals to
     * Constants.AST_SETTINGS_JSON then settings are defined via two JSONs, if
     * equals to Constants.AST_SETTINGS_UI then settings are defined via viewer
     */
    public static final String AST_SETTINGS = PARAM("ScanSettings");
    /**
     * PT AI project name whose AST settings are used if AST_SETTINGS equals
     * to  Constants.AST_SETTINGS_UI
     */
    public static final String PROJECT_NAME = PARAM("ProjectName");
    /**
     * AST settings defined via JSON. This value used if AST_SETTINGS equals
     * to Constants.AST_SETTINGS_JSON
     */
    public static final String JSON_SETTINGS = PARAM("JsonSettings");
    /**
     * AST policy (optional value) defined via JSON. This value used if
     * AST_SETTINGS equals to Constants.AST_SETTINGS_JSON
     */
    public static final String JSON_POLICY = PARAM("JsonPolicy");

    /**
     * What to do if AST policy assessment failed. If equals to Constants.TRUE
     * then build step will be marked as failed
     */
    public static final String FAIL_IF_FAILED = PARAM("FailIfFailed");
    /**
     * What to do if there were minor warnings during AST (i.e. aic.exe
     * returned exit code 6). If equals to Constants.TRUE then build
     * step will be marked as failed
     */
    public static final String FAIL_IF_UNSTABLE = PARAM("FailIfUnstable");
    /**
     * PT AI agent node name or tag where AST is to be executed. Allows to implement
     * load balancing if PT AI is being shared between multiple R&D teams
     */
    public static final String NODE_NAME = PARAM("NodeName");
    /**
     * Allows verbose logging if equals to Constants.TRUE
     */
    public static final String VERBOSE = PARAM("Verbose");
    public static final String INCLUDES = PARAM("Includes");
    public static final String REMOVE_PREFIX = PARAM("RemovePrefix");
    public static final String EXCLUDES = PARAM("Excludes");
    public static final String PATTERN_SEPARATOR = PARAM("PatternSeparator");
    public static final String USE_DEFAULT_EXCLUDES = PARAM("UseDefaultExcludes");
    public static final String FLATTEN = PARAM("Flatten");

    private static String PARAM(final String field) {
        // return PREFIX + "." + String.valueOf(field.charAt(0)).toLowerCase() + field.substring(1);
        return PREFIX + String.valueOf(field.charAt(0)).toUpperCase() + field.substring(1);
    }
}
