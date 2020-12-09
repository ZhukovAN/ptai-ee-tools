package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;

/**
 * Default parameter values that are used in plugin settings
 */
public class Defaults {
    // PT AI connection parameter names
    public static final String URL = "https://ptai.domain.corp:8443";
    public static final String TOKEN = "P@ssw0rd";
    public static final String CERTIFICATES = "";
    public static final String INSECURE = FALSE;
    /**
     * Field that stores scan settings type: UI- or JSON-based. If this
     * field equals to Constants.SERVER_SETTINGS_GLOBAL then globally defined PT AI
     * server connection settings will be used
     * (see URL..CERTIFICATES). If equals to
     * Constants.CONFIG_LOCAL then PT AI server connection settings are
     * defined as a build step parameters
     */
    public static final String SERVER_SETTINGS = SERVER_SETTINGS_GLOBAL;
    /**
     * Defines how code AST settings are defined. If this field equals to
     * Constants.AST_SETTINGS_JSON then settings are defined via two JSONs, if
     * equals to Constants.AST_SETTINGS_UI then settings are defined via viewer
     */
    public static final String AST_SETTINGS = AST_SETTINGS_UI;
    /**
     * PT AI project name whose AST settings are used if AST_SETTINGS equals
     * to  Constants.AST_SETTINGS_UI
     */
    public static final String PROJECT_NAME = "PROJECT";
    /**
     * AST settings defined via JSON. This value used if AST_SETTINGS equals
     * to Constants.AST_SETTINGS_JSON
     */
    // TODO: Add minimal JSON settings from resource
    public static final String JSON_SETTINGS = "";
    /**
     * AST policy (optional value) defined via JSON. This value used if
     * AST_SETTINGS equals to Constants.AST_SETTINGS_JSON
     */
    public static final String JSON_POLICY = "[]";
    /**
     * What to do if AST policy assessment failed. If equals to Constants.TRUE
     * then build step will be marked as failed
     */
    public static final String FAIL_IF_FAILED = TRUE;
    /**
     * What to do if there were minor warnings during AST (i.e. aic.exe
     * returned exit code 6). If equals to Constants.TRUE then build
     * step will be marked as failed
     */
    public static final String FAIL_IF_UNSTABLE = FALSE;
    /**
     * Allows verbose logging if equals to Constants.TRUE
     */
    public static final String VERBOSE = FALSE;
    public static final String INCLUDES = Transfer.DEFAULT_INCLUDES;
    public static final String REMOVE_PREFIX = "";
    public static final String EXCLUDES = Transfer.DEFAULT_EXCLUDES;
    public static final String PATTERN_SEPARATOR = Transfer.DEFAULT_PATTERN_SEPARATOR;
    public static final String USE_DEFAULT_EXCLUDES = Transfer.DEFAULT_USE_DEFAULT_EXCLUDES ? TRUE : FALSE;
    public static final String FLATTEN = Transfer.DEFAULT_FLATTEN ? TRUE : FALSE;

    public static final String REPORT_SETTINGS = REPORT_SETTINGS_NONE;
}
