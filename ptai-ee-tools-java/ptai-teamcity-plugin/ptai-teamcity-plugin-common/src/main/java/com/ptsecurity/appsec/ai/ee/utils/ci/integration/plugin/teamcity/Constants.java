package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

public class Constants {
    /**
     * Value of mode parameter when user clicks on "save" button
     */
    public static final String MODE_SAVE = "save";

    /**
     * Value of mode parameter when user clicks on "test" button
     */
    public static final String MODE_TEST = "test";

    /**
     * Value of mode parameter when user performs any action on a
     * form with updateState event handler set up
     */
    public static final String MODE_MODIFY = "modify";

    public static final String PREFIX = "ptai";
    public static final String PLUGIN_NAME = "ptsecurity";
    public static final String RUNNER_TYPE = PLUGIN_NAME;

    public static final String ADMIN_CONTROLLER_PATH = "/" + PREFIX + "/admin.html";
    public static final String AST_CONTROLLER_PATH = "/" + PREFIX + "/ast.html";

    public static final String SUCCESS = "SUCCESS";
    public static final String FAILURE = "FAILURE";

    public static final String TRUE = "true";
    public static final String FALSE = "false";

    public static final String AST_SETTINGS_JSON = "SettingsJson";
    public static final String AST_SETTINGS_UI = "SettingsUI";

    public static final String SERVER_SETTINGS_GLOBAL = "SettingsGlobal";
    public static final String SERVER_SETTINGS_LOCAL = "SettingsTask";

    public static final String REPORT_SETTINGS_NONE = "ReportNone";
    public static final String REPORT_SETTINGS_SINGLE = "ReportSingle";
    public static final String REPORT_SETTINGS_JSON = "ReportJson";

}
