package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;

public class Constants {
    /**
     * Value of mode parameter when user clicks on "Save" button
     */
    public static final String MODE_SAVE = "save";

    /**
     * Value of mode parameter when user clicks on "Test" button
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

    public static final String EMPTY = "";

    public static final String TRUE = "true";
    public static final String FALSE = "false";

    public static final String AST_SETTINGS_JSON = "SettingsJson";
    public static final String AST_SETTINGS_UI = "SettingsUI";

    public static final String SERVER_SETTINGS_GLOBAL = "SettingsGlobal";
    public static final String SERVER_SETTINGS_LOCAL = "SettingsTask";

    /**
     * AST job is to be executed in synchronous mode i.e. CI system will wait
     * for job to finish, then look at the AST policy assessment results, generate reports etc.
     */
    public static final String AST_MODE_SYNC = "AstModeSync";
    /**
     * AST job is to be executed in asynchronous mode i.e. CI system will not wai for job to complete
     */
    public static final String AST_MODE_ASYNC = "AstModeAsync";

    public static final String REPORTING_LOCALE_ENGLISH = Reports.Locale.EN.getValue();
    public static final String REPORTING_LOCALE_RUSSIAN = Reports.Locale.RU.getValue();

    public static final String REPORTING_DATA_FORMAT_XML = Reports.Data.Format.XML.name();
    public static final String REPORTING_DATA_FORMAT_JSON = Reports.Data.Format.JSON.name();
    public static final String REPORTING_REPORT_FORMAT_HTML = Reports.Report.Format.HTML.name();
    public static final String REPORTING_REPORT_FORMAT_PDF = Reports.Report.Format.PDF.name();
}
