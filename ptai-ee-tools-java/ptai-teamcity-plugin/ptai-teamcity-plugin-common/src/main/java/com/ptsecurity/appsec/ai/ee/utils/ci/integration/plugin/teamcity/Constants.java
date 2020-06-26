package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

public class Constants {
    public static final String PREFIX = "ptai";
    public static final String PLUGIN_NAME = "ptsecurity";
    public static final String RUNNER_TYPE = PLUGIN_NAME;

    public static final String ADMIN_CONTROLLER_PATH = "/" + PREFIX + "/adminSettings.html";
    public static final String TEST_CONTROLLER_PATH = "/" + PREFIX + "/testSettings.html";

    /**
     * OAuth client ID
     */
    public static final String CLIENT_ID = "ptai-teamcity-plugin";
    /**
     * OAuth client secret
     */
    public static final String CLIENT_SECRET = "ZW3r0QB3YFZvhmG8pmYDMC0VtGP0IC17";

    public static final String TRUE = "true";
    public static final String FALSE = "false";

    public static final String AST_SETTINGS_JSON = "SettingsJson";
    public static final String AST_SETTINGS_UI = "SettingsUI";

    public static final String SERVER_SETTINGS_GLOBAL = "SettingsGlobal";
    public static final String SERVER_SETTINGS_LOCAL = "SettingsTask";


}
