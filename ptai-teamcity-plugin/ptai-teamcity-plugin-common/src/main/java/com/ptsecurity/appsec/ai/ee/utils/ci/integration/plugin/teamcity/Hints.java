package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.StringHelper;

import java.util.Arrays;

/**
 * Class contains constants that are used as a hints in UI
 */
public class Hints {
    public static final String RUNNER = "PT AI AST scan";

    public static final String URL = Resources.i18n_ast_settings_server_url_hint();
    public static final String TOKEN = Resources.i18n_ast_settings_server_token_hint();
    public static final String CERTIFICATES = Resources.i18n_ast_settings_server_ca_pem_hint();
    public static final String INSECURE = Resources.i18n_ast_settings_server_insecure_hint();

    public static final String SERVER_SETTINGS = "Choose how PT AI server connection settings are defined";
    public static final String SERVER_SETTINGS_GLOBAL = "Global scope defined PT AI server config";
    public static final String SERVER_SETTINIGS_LOCAL = "Task scope defined PT AI server config";

    public static final String AST_SETTINGS = "Choose how AST settings are defined";
    public static final String AST_SETTINGS_JSON = "JSON-defined settings";
    public static final String AST_SETTINGS_UI = "PT AI viewer-defined settings";

    public static final String PROJECT_NAME = "Project name as it defined in PT AI Viewer UI";
    public static final String JSON_SETTINGS = "Scan settings in JSON format";
    public static final String JSON_POLICY =
            "Project SAST policy in JSON format." +
                    "<br>" +
                    "If this parameter is empty then SAST policy will be downloaded from PT AI EE server." +
                    "<br>" +
                    "If you need to scan project without policy use [] value";

    public static final String AST_MODE = Resources.i18n_ast_settings_mode_hint();
    public static final String AST_MODE_SYNC = Resources.i18n_ast_settings_mode_synchronous_hint();
    public static final String AST_MODE_ASYNC = Resources.i18n_ast_settings_mode_asynchronous_hint();

    public static final String FAIL_IF_FAILED = "Mark build step as failed if AST policy assessment failed";
    public static final String FAIL_IF_UNSTABLE = "Mark build step as failed if AST policy assessment success but there were some minor warnings reported";
    public static final String FULL_SCAN_MODE = Resources.i18n_ast_settings_fullScanMode_hint();
    public static final String VERBOSE = Resources.i18n_ast_settings_verbose_hint();

    public static final String INCLUDES =
            "Files to scan for vulnerabilities. The string is a comma separated " +
                    "list of includes for an Ant fileset eg. '**/*.jar' " +
                    "(see <a href=\"http://ant.apache.org/manual/dirtasks.html#patterns\">Patterns</a> " +
                    "in the Ant manual). The base directory for this fileset is the workspace";
    public static final String REMOVE_PREFIX = "First part of the file path that should not be created on the remote server";
    public static final String EXCLUDES =
            "Exclude files from the Transfer set. The string is a comma separated " +
                    "list of excludes for an Ant fileset eg. '**/*.log, **/*.tmp, .git/' " +
                    "(see <a href=\"http://ant.apache.org/manual/dirtasks.html#patterns\">Patterns</a> " +
                    "in the Ant manual)";
    public static final String PATTERN_SEPARATOR = "The regular expression that is used to separate the Source files and Exclude files patterns";
    public static final String USE_DEFAULT_EXCLUDES =
            "Select this option to disable the default exclude patterns (" +
                    StringHelper.joinListGrammatically(Arrays.asList(FileCollector.defaultExcludes())) +
                    ")";
    public static final String FLATTEN = "Only transfer files, ignore folder structure";

    /**
     * See {@link Params#REPORTING_REPORT}
     */
    public static final String REPORTING_REPORT = Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_hint();

    /**
     * See {@link Params#REPORTING_DATA}
     */
    public static final String REPORTING_DATA = Resources.i18n_ast_settings_mode_synchronous_subjob_export_jsonxml_hint();

    /**
     * See {@link Params#REPORTING_RAWDATA}
     */
    public static final String REPORTING_RAWDATA = Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_hint();
    /**
     * See {@link Params#REPORTING_SARIF}
     */
    public static final String REPORTING_SARIF = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sarif_hint();
    /**
     * See {@link Params#REPORTING_SONARGIIF}
     */
    public static final String REPORTING_SONARGIIF = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_hint();
    /**
     * See {@link Params#REPORTING_JSON}
     */
    public static final String REPORTING_JSON = Resources.i18n_ast_settings_mode_synchronous_subjob_export_advanced_hint();

    /**
     * See {@link Params#REPORTING_REPORT_FILE}
     */
    public static final String REPORTING_REPORT_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_file_hint();

    /**
     * See {@link Params#REPORTING_REPORT_TEMPLATE}
     */
    public static final String REPORTING_REPORT_TEMPLATE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_template_hint();

    /**
     * See {@link Params#REPORTING_REPORT_FORMAT}
     */
    public static final String REPORTING_REPORT_FORMAT = Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_format_hint();

    /**
     * See {@link Params#REPORTING_REPORT_LOCALE}
     */
    public static final String REPORTING_REPORT_LOCALE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_locale_hint();

    /**
     * See {@link Params#REPORTING_REPORT_FILTER}
     */
    public static final String REPORTING_REPORT_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_htmlpdf_filter_hint();

    /**
     * See {@link Params#REPORTING_DATA_FILE}
     */
    public static final String REPORTING_DATA_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_jsonxml_file_hint();

    /**
     * See {@link Params#REPORTING_DATA_FORMAT}
     */
    public static final String REPORTING_DATA_FORMAT = Resources.i18n_ast_settings_mode_synchronous_subjob_export_jsonxml_format_hint();

    /**
     * See {@link Params#REPORTING_DATA_LOCALE}
     */
    public static final String REPORTING_DATA_LOCALE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_jsonxml_locale_hint();

    /**
     * See {@link Params#REPORTING_DATA_FILTER}
     */
    public static final String REPORTING_DATA_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_jsonxml_filter_hint();

    /**
     * See {@link Params#REPORTING_RAWDATA_FILE}
     */
    public static final String REPORTING_RAWDATA_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_file_hint();

    /**
     * See {@link Params#REPORTING_RAWDATA_FILTER}
     */
    public static final String REPORTING_RAWDATA_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_rawjson_filter_hint();

    /**
     * See {@link Params#REPORTING_SARIF_FILE}
     */
    public static final String REPORTING_SARIF_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sarif_file_hint();

    /**
     * See {@link Params#REPORTING_SARIF_FILTER}
     */
    public static final String REPORTING_SARIF_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sarif_filter_hint();

    /**
     * See {@link Params#REPORTING_SONARGIIF_FILE}
     */
    public static final String REPORTING_SONARGIIF_FILE = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_file_hint();

    /**
     * See {@link Params#REPORTING_SONARGIIF_FILTER}
     */
    public static final String REPORTING_SONARGIIF_FILTER = Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_filter_hint();

    /**
     * See {@link Params#REPORTING_JSON_SETTINGS}
     */
    public static final String REPORTING_JSON_SETTINGS = Resources.i18n_ast_settings_mode_synchronous_subjob_export_advanced_settings_hint();
}
