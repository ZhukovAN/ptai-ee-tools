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
    public static final String INSECURE = PARAM("Insecure");

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
     * Allows verbose logging if equals to Constants.TRUE
     */
    public static final String VERBOSE = PARAM("Verbose");
    public static final String INCLUDES = PARAM("Includes");
    public static final String REMOVE_PREFIX = PARAM("RemovePrefix");
    public static final String EXCLUDES = PARAM("Excludes");
    public static final String PATTERN_SEPARATOR = PARAM("PatternSeparator");
    public static final String USE_DEFAULT_EXCLUDES = PARAM("UseDefaultExcludes");
    public static final String FLATTEN = PARAM("Flatten");

    /**
     * Defines what are the reports to be generated. If this field equals to
     * Constants.REPORT_SETTINGS_NONE then no report will be generated at all. If field
     * equals to Constants.REPORT_SETTINGS_SINGLE then single report with template TEMPLATE_NAME,
     * format REPORT_FORMAT and locale REPORT_LOCALE will be generated. And if
     * this field equals to Constants.REPORT_SETTINGS_JSON then full set of reports as defined in JSON AST_SETTINGS_UI then settings are defined via viewer
     */
    public static final String REPORT_SETTINGS = PARAM("ReportSettings");

    /**
     * PT AI report template name that will be used for report generation
     * if REPORT_SETTINGS equals to Constants.REPORT_SETTINGS_SINGLE
     */
    public static final String REPORT_TEMPLATE_NAME = PARAM("ReportTemplateName");

    /**
     * PT AI report format that will be used for report generation
     * if REPORT_SETTINGS equals to Constants.REPORT_SETTINGS_SINGLE
     */
    public static final String REPORT_FORMAT = PARAM("ReportFormat");

    /**
     * PT AI report locale ID that will be used for report generation
     * if REPORT_SETTINGS equals to Constants.REPORT_SETTINGS_SINGLE
     */
    public static final String REPORT_LOCALE = PARAM("ReportLocale");

    /**
     * PT AI reports generation JSON that will be used for report generation
     * if REPORT_SETTINGS field value equals to Constants.REPORT_SETTINGS_JSON
     */
    public static final String REPORT_JSON = PARAM("ReportJson");

    private static String PARAM(final String field) {
        // return PREFIX + "." + String.valueOf(field.charAt(0)).toLowerCase() + field.substring(1);
        return PREFIX + String.valueOf(field.charAt(0)).toUpperCase() + field.substring(1);
    }
}
