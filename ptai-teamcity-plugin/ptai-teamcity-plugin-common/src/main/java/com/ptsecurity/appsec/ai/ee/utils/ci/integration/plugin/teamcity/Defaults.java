package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.lang.reflect.Field;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;

/**
 * Default parameter values that are used in plugin settings
 */
public class Defaults {

    /**
     * See {@link Params#URL}
     */
    public static final String URL = AbstractJob.DEFAULT_PTAI_URL;

    /**
     * See {@link Params#TOKEN}
     */
    public static final String TOKEN = "P@ssw0rd";

    /**
     * See {@link Params#CERTIFICATES}
     */
    public static final String CERTIFICATES = "";

    /**
     * See {@link Params#INSECURE}
     */
    public static final String INSECURE = TRUE;

    /**
     * See {@link Params#SERVER_SETTINGS} and {@link Constants#SERVER_SETTINGS_GLOBAL}
     */
    public static final String SERVER_SETTINGS = SERVER_SETTINGS_GLOBAL;

    /**
     * See {@link Params#AST_SETTINGS} and {@link Constants#AST_SETTINGS_UI}
     */
    public static final String AST_SETTINGS = AST_SETTINGS_UI;

    /**
     * See {@link Params#PROJECT_NAME}
     */
    public static final String PROJECT_NAME = "PROJECT";

    /**
     * See {@link Params#JSON_SETTINGS}
     */
    // TODO: Add minimal JSON settings from resource
    public static final String JSON_SETTINGS = "";

    /**
     * See {@link Params#JSON_POLICY}
     */
    public static final String JSON_POLICY = "[]";

    /**
     * See {@link Params#AST_MODE} and {@link Constants#AST_MODE_SYNC}
     */
    public static final String AST_MODE = AST_MODE_SYNC;

    /**
     * See {@link Params#FAIL_IF_FAILED}
     */
    public static final String FAIL_IF_FAILED = TRUE;

    /**
     * See {@link Params#FAIL_IF_UNSTABLE}
     */
    public static final String FAIL_IF_UNSTABLE = FALSE;

    /**
     * See {@link Params#FULL_SCAN_MODE}
     */
    public static final String FULL_SCAN_MODE = FALSE;

    /**
     * See {@link Params#VERBOSE}
     */
    public static final String VERBOSE = FALSE;

    /**
     * See {@link Params#INCLUDES} and {@link Transfer#DEFAULT_INCLUDES}
     */
    public static final String INCLUDES = Transfer.DEFAULT_INCLUDES;

    /**
     * See {@link Params#REMOVE_PREFIX}
     */
    public static final String REMOVE_PREFIX = "";

    /**
     * See {@link Params#EXCLUDES} and {@link Transfer#DEFAULT_EXCLUDES}
     */
    public static final String EXCLUDES = Transfer.DEFAULT_EXCLUDES;

    /**
     * See {@link Params#PATTERN_SEPARATOR} and {@link Transfer#DEFAULT_PATTERN_SEPARATOR}
     */
    public static final String PATTERN_SEPARATOR = Transfer.DEFAULT_PATTERN_SEPARATOR;

    /**
     * See {@link Params#USE_DEFAULT_EXCLUDES} and {@link Transfer#DEFAULT_USE_DEFAULT_EXCLUDES}
     */
    public static final String USE_DEFAULT_EXCLUDES = Transfer.DEFAULT_USE_DEFAULT_EXCLUDES ? TRUE : FALSE;

    /**
     * See {@link Params#FLATTEN} and {@link Transfer#DEFAULT_FLATTEN}
     */
    public static final String FLATTEN = Transfer.DEFAULT_FLATTEN ? TRUE : FALSE;

    /**
     * See {@link Params#REPORTING_REPORT}
     */
    public static final String REPORTING_REPORT = FALSE;

    /**
     * See {@link Params#REPORTING_DATA}
     */
    public static final String REPORTING_DATA = FALSE;

    /**
     * See {@link Params#REPORTING_RAWDATA}
     */
    public static final String REPORTING_RAWDATA = FALSE;

    /**
     * See {@link Params#REPORTING_JSON}
     */
    public static final String REPORTING_JSON = FALSE;

    /**
     * See {@link Params#REPORTING_REPORT_FILE}
     */
    public static final String REPORTING_REPORT_FILE = EMPTY;

    /**
     * See {@link Params#REPORTING_REPORT_TEMPLATE}
     */
    public static final String REPORTING_REPORT_TEMPLATE = EMPTY;

    /**
     * See {@link Params#REPORTING_REPORT_FORMAT}
     */
    public static final String REPORTING_REPORT_FORMAT = Reports.Report.DEFAULT_FORMAT;

    /**
     * See {@link Params#REPORTING_REPORT_LOCALE}
     */
    public static final String REPORTING_REPORT_LOCALE = Reports.Report.DEFAULT_LOCALE;

    /**
     * See {@link Params#REPORTING_REPORT_FILTER}
     */
    public static final String REPORTING_REPORT_FILTER = EMPTY;

    /**
     * See {@link Params#REPORTING_DATA_FILE}
     */
    public static final String REPORTING_DATA_FILE = EMPTY;

    /**
     * See {@link Params#REPORTING_DATA_FORMAT}
     */
    public static final String REPORTING_DATA_FORMAT = Reports.Data.DEFAULT_FORMAT;

    /**
     * See {@link Params#REPORTING_DATA_LOCALE}
     */
    public static final String REPORTING_DATA_LOCALE = Reports.Data.DEFAULT_LOCALE;

    /**
     * See {@link Params#REPORTING_DATA_FILTER}
     */
    public static final String REPORTING_DATA_FILTER = EMPTY;

    /**
     * See {@link Params#REPORTING_RAWDATA_FILE}
     */
    public static final String REPORTING_RAWDATA_FILE = EMPTY;

    /**
     * See {@link Params#REPORTING_JSON_SETTINGS}
     */
    public static final String REPORTING_JSON_SETTINGS = EMPTY;

    /**
     * Method returns default value for field passed by its name. This is implemented
     * using reflection and required to optimize functions like creation of property map with default field values
     * @param fieldName Defaults's public static final String field name like "URL" or "SERVER_SETTINGS"
     * @return Field's default value
     */
    @SneakyThrows
    public static String value(@NonNull final String fieldName) {
        Field field = Defaults.class.getField(fieldName);
        return (String) field.get(null);
    }
}
