package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import lombok.NonNull;
import lombok.SneakyThrows;

import java.lang.reflect.Field;

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
     * field equals to {@link Constants#SERVER_SETTINGS_GLOBAL} then globally defined PT AI
     * server connection settings will be used
     * (see URL..CERTIFICATES). If equals to
     * {@link Constants#SERVER_SETTINGS_LOCAL} then PT AI server connection settings are
     * defined as a build step parameters
     */
    public static final String SERVER_SETTINGS = PARAM("ServerSettings");

    /**
     * Defines how code AST settings are defined. If this field equals to
     * {@link Constants#AST_SETTINGS_JSON} then settings are defined via two JSONs, if
     * equals to {@link Constants#AST_SETTINGS_UI} then settings are defined via viewer
     */
    public static final String AST_SETTINGS = PARAM("ScanSettings");

    /**
     * PT AI project name whose AST settings are used if AST_SETTINGS equals
     * to  {@link Constants#AST_SETTINGS_UI}
     */
    public static final String PROJECT_NAME = PARAM("ProjectName");

    /**
     * AST settings defined via JSON. This value used if AST_SETTINGS equals
     * to {@link Constants#AST_SETTINGS_JSON}
     */
    public static final String JSON_SETTINGS = PARAM("JsonSettings");

    /**
     * AST policy (optional value) defined via JSON. This value used if
     * AST_SETTINGS equals to {@link Constants#AST_SETTINGS_JSON}
     */
    public static final String JSON_POLICY = PARAM("JsonPolicy");

    /**
     * Defines how AST job is to be started. If this field equals to {@link Constants#AST_MODE_SYNC}
     * then CI will wait for job to complete. If {@link Constants#AST_MODE_ASYNC} used then plugin
     * will only upload sources to PT AI server, start scan and return control flow to CI
     */
    public static final String AST_MODE = PARAM("AstMode");

    /**
     * What to do if AST policy assessment failed. If equals to {@link Constants#TRUE}
     * then build step will be marked as failed
     */
    public static final String FAIL_IF_FAILED = PARAM("FailIfFailed");

    /**
     * What to do if there were minor warnings during AST (i.e. aic.exe
     * returned exit code 6). If equals to {@link Constants#TRUE} then build
     * step will be marked as failed
     */
    public static final String FAIL_IF_UNSTABLE = PARAM("FailIfUnstable");

    /**
     * Allows execute AST in full (i.e. non-incremental) mode if equals to {@link Constants#TRUE}
     */
    public static final String FULL_SCAN_MODE = PARAM("FullScanMode");
    /**
     * Allows verbose logging if equals to {@link Constants#TRUE}
     */
    public static final String VERBOSE = PARAM("Verbose");
    public static final String INCLUDES = PARAM("Includes");
    public static final String REMOVE_PREFIX = PARAM("RemovePrefix");
    public static final String EXCLUDES = PARAM("Excludes");
    public static final String PATTERN_SEPARATOR = PARAM("PatternSeparator");
    public static final String USE_DEFAULT_EXCLUDES = PARAM("UseDefaultExcludes");
    public static final String FLATTEN = PARAM("Flatten");

    /**
     * If this field value equals to {@link Constants#TRUE} then generic HTML or PDF report
     * will be generated. User also need to provide report file name, template, format, locale and optional filters
     */
    public static final String REPORTING_REPORT = PARAM("ReportingReport");

    /**
     * If this field value equals to {@link Constants#TRUE} then generic data will be exported as
     * XML or JSON file. User also need to provide output file name, format, locale and optional filters
     */
    public static final String REPORTING_DATA = PARAM("ReportingData");

    /**
     * If this field value equals to {@link Constants#TRUE} then raw vulnerabilities data will be exported as
     * JSON file. User also need to provide output file name
     */
    public static final String REPORTING_RAWDATA = PARAM("ReportingRawData");

    /**
     * If this field value equals to {@link Constants#TRUE} then raw vulnerabilities data will be exported as
     * SARIF JSON file. User also need to provide output file name
     */
    public static final String REPORTING_SARIF = PARAM("ReportingSarif");

    /**
     * If this field value equals to {@link Constants#TRUE} then raw vulnerabilities data will be exported as
     * SonarQube GIIF JSON file. User also need to provide output file name
     */
    public static final String REPORTING_SONARGIIF = PARAM("ReportingSonarGiif");

    /**
     * If this field value equals to {@link Constants#TRUE} then JSON-defined
     * reports and data exports will be done
     */
    public static final String REPORTING_JSON = PARAM("ReportingJson");

    /**
     * If {@link Params#REPORTING_REPORT} is on then this field is to
     * contain name of the file where report will be saved to
     */
    public static final String REPORTING_REPORT_FILE = PARAM("ReportingReportFile");

    /**
     * If {@link Params#REPORTING_REPORT} is on then this field is to
     * contain name of the report template
     */
    public static final String REPORTING_REPORT_TEMPLATE = PARAM("ReportingReportTemplate");

    /**
     * If {@link Params#REPORTING_REPORT} is on then this field is to
     * contain format of the report file to be generated
     */
    public static final String REPORTING_REPORT_FORMAT = PARAM("ReportingReportFormat");

    /**
     * If {@link Params#REPORTING_REPORT} is on then this field is to
     * contain locale of the report file to be generated
     */
    public static final String REPORTING_REPORT_LOCALE = PARAM("ReportingReportLocale");

    /**
     * If {@link Params#REPORTING_REPORT} is on then this field may
     * contain JSON filter to define vulnerabilities to be included in the generated report file
     */
    public static final String REPORTING_REPORT_FILTER = PARAM("ReportingReportFilter");

    /**
     * If {@link Params#REPORTING_DATA} is on then this field is to
     * contain name of the file where AST data will be saved to
     */
    public static final String REPORTING_DATA_FILE = PARAM("ReportingDataFile");

    /**
     * If {@link Params#REPORTING_DATA} is on then this field is to
     * contain format of the data export file to be generated
     */
    public static final String REPORTING_DATA_FORMAT = PARAM("ReportingDataFormat");

    /**
     * If {@link Params#REPORTING_DATA} is on then this field is to
     * contain locale of the data export file to be generated
     */
    public static final String REPORTING_DATA_LOCALE = PARAM("ReportingDataLocale");

    /**
     * If {@link Params#REPORTING_DATA} is on then this field may
     * contain JSON filter to define vulnerabilities to be included in the generated data export file
     */
    public static final String REPORTING_DATA_FILTER = PARAM("ReportingDataFilter");

    /**
     * If {@link Params#REPORTING_RAWDATA} is on then this field is to
     * contain name of the file where raw AST data will be saved to
     */
    public static final String REPORTING_RAWDATA_FILE = PARAM("ReportingRawDataFile");

    /**
     * If {@link Params#REPORTING_RAWDATA} is on then this field may
     * contain JSON filter to define vulnerabilities to be included in the generated raw data export file
     */
    public static final String REPORTING_RAWDATA_FILTER = PARAM("ReportingRawDataFilter");

    /**
     * If {@link Params#REPORTING_SARIF} is on then this field is to
     * contain name of the file where raw SARIF JSON data will be saved to
     */
    public static final String REPORTING_SARIF_FILE = PARAM("ReportingSarifFile");

    /**
     * If {@link Params#REPORTING_SARIF} is on then this field may
     * contain JSON filter to define vulnerabilities to be included in the generated SARIF export file
     */
    public static final String REPORTING_SARIF_FILTER = PARAM("ReportingSarifFilter");

    /**
     * If {@link Params#REPORTING_SONARGIIF} is on then this field is to
     * contain name of the file where SonarQube GIIF JSON data will be saved to
     */
    public static final String REPORTING_SONARGIIF_FILE = PARAM("ReportingSonarGiifFile");

    /**
     * If {@link Params#REPORTING_SONARGIIF} is on then this field may
     * contain JSON filter to define vulnerabilities to be included in the generated SonarQube GIIF export file
     */
    public static final String REPORTING_SONARGIIF_FILTER = PARAM("ReportingSonarGiifFilter");

    /**
     * If {@link Params#REPORTING_JSON} is on then this field is to
     * contain JSON definition of reports or data exports to be generated
     */
    public static final String REPORTING_JSON_SETTINGS = PARAM("ReportingJsonSettings");

    public static String PARAM(final String field) {
        String res = PREFIX + String.valueOf(field.charAt(0)).toUpperCase() + field.substring(1);
        return res;
    }

    /**
     * Method returns parameter name for field passed by its name. This is implemented
     * using reflection and required to optimize functions like creation of property map with default field values
     * @param fieldName Defaults's public static final String field name like "URL" or "SERVER_SETTINGS"
     * @return Parameter name
     */
    @SneakyThrows
    public static String value(@NonNull final String fieldName) {
        Field field = Params.class.getField(fieldName);
        return (String) field.get(null);
    }

}
