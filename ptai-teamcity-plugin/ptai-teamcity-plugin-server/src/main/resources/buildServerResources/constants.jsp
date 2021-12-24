<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Hints" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params" %>

<c:set var="SERVER_SETTINGS_GLOBAL_URL" value="<%=Params.URL%>"/>
<c:set var="LABEL_SERVER_SETTINGS_GLOBAL_URL" value="<%=Labels.URL%>"/>
<c:set var="HINT_SERVER_SETTINGS_GLOBAL_URL" value="<%=Hints.URL%>"/>

<c:set var="SERVER_SETTINGS_GLOBAL_TOKEN" value="<%=Params.TOKEN%>"/>
<c:set var="LABEL_SERVER_SETTINGS_GLOBAL_TOKEN" value="<%=Labels.TOKEN%>"/>
<c:set var="HINT_SERVER_SETTINGS_GLOBAL_TOKEN" value="<%=Hints.TOKEN%>"/>

<c:set var="SERVER_SETTINGS_GLOBAL_CERTIFICATES" value="<%=Params.CERTIFICATES%>"/>
<c:set var="LABEL_SERVER_SETTINGS_GLOBAL_CERTIFICATES" value="<%=Labels.CERTIFICATES%>"/>
<c:set var="HINT_SERVER_SETTINGS_GLOBAL_CERTIFICATES" value="<%=Hints.CERTIFICATES%>"/>

<c:set var="SERVER_SETTINGS_GLOBAL_INSECURE" value="<%=Params.INSECURE%>"/>
<c:set var="LABEL_SERVER_SETTINGS_GLOBAL_INSECURE" value="<%=Labels.INSECURE%>"/>
<c:set var="HINT_SERVER_SETTINGS_GLOBAL_INSECURE" value="<%=Hints.INSECURE%>"/>

<c:set var="SERVER_SETTINGS" value="<%=Params.SERVER_SETTINGS%>"/>
<c:set var="LABEL_SERVER_SETTINGS" value="<%=Labels.SERVER_SETTINGS%>"/>
<c:set var="HINT_SERVER_SETTINGS" value="<%=Hints.SERVER_SETTINGS%>"/>
<%-- Server settings combobox content --%>
<c:set var="LABEL_SERVER_SETTINGS_GLOBAL" value="<%=Labels.SERVER_SETTINGS_GLOBAL%>"/>
<c:set var="HINT_SERVER_SETTINGS_GLOBAL" value="<%=Hints.SERVER_SETTINGS_GLOBAL%>"/>
<c:set var="SERVER_SETTINGS_GLOBAL" value="<%=Constants.SERVER_SETTINGS_GLOBAL%>"/>
<c:set var="LABEL_SERVER_SETTINGS_LOCAL" value="<%=Labels.SERVER_SETTINGS_LOCAL%>"/>
<c:set var="HINT_SERVER_SETTINGS_LOCAL" value="<%=Hints.SERVER_SETTINIGS_LOCAL%>"/>
<c:set var="SERVER_SETTINGS_LOCAL" value="<%=Constants.SERVER_SETTINGS_LOCAL%>"/>

<c:set var="SERVER_SETTINGS_LOCAL_URL" value="<%=Params.URL%>"/>
<c:set var="LABEL_SERVER_SETTINGS_LOCAL_URL" value="<%=Labels.URL%>"/>
<c:set var="HINT_SERVER_SETTINGS_LOCAL_URL" value="<%=Hints.URL%>"/>

<c:set var="SERVER_SETTINGS_LOCAL_TOKEN" value="<%=Params.TOKEN%>"/>
<c:set var="LABEL_SERVER_SETTINGS_LOCAL_TOKEN" value="<%=Labels.TOKEN%>"/>
<c:set var="HINT_SERVER_SETTINGS_LOCAL_TOKEN" value="<%=Hints.TOKEN%>"/>

<c:set var="SERVER_SETTINGS_LOCAL_CERTIFICATES" value="<%=Params.CERTIFICATES%>"/>
<c:set var="LABEL_SERVER_SETTINGS_LOCAL_CERTIFICATES" value="<%=Labels.CERTIFICATES%>"/>
<c:set var="HINT_SERVER_SETTINGS_LOCAL_CERTIFICATES" value="<%=Hints.CERTIFICATES%>"/>

<c:set var="SERVER_SETTINGS_LOCAL_INSECURE" value="<%=Params.INSECURE%>"/>
<c:set var="LABEL_SERVER_SETTINGS_LOCAL_INSECURE" value="<%=Labels.INSECURE%>"/>
<c:set var="HINT_SERVER_SETTINGS_LOCAL_INSECURE" value="<%=Hints.INSECURE%>"/>


<c:set var="AST_SETTINGS" value="<%=Params.AST_SETTINGS%>"/>
<c:set var="LABEL_AST_SETTINGS" value="<%=Labels.AST_SETTINGS%>"/>
<c:set var="HINT_AST_SETTINGS" value="<%=Hints.AST_SETTINGS%>"/>
<%-- Scan settings combobox content --%>
<c:set var="AST_SETTINGS_UI" value="<%=Constants.AST_SETTINGS_UI%>"/>
<c:set var="LABEL_AST_SETTINGS_UI" value="<%=Labels.AST_SETTINGS_UI%>"/>
<c:set var="HINT_AST_SETTINGS_UI" value="<%=Hints.AST_SETTINGS_UI%>"/>
<c:set var="AST_SETTINGS_JSON" value="<%=Constants.AST_SETTINGS_JSON%>"/>
<c:set var="LABEL_AST_SETTINGS_JSON" value="<%=Labels.AST_SETTINGS_JSON%>"/>
<c:set var="HINT_AST_SETTINGS_JSON" value="<%=Hints.AST_SETTINGS_JSON%>"/>

<c:set var="AST_SETTINGS_UI_PROJECT_NAME" value="<%=Params.PROJECT_NAME%>"/>
<c:set var="LABEL_AST_SETTINGS_UI_PROJECT_NAME" value="<%=Labels.PROJECT_NAME%>"/>
<c:set var="HINT_AST_SETTINGS_UI_PROJECT_NAME" value="<%=Hints.PROJECT_NAME%>"/>

<c:set var="AST_SETTINGS_JSON_SETTINGS" value="<%=Params.JSON_SETTINGS%>"/>
<c:set var="LABEL_AST_SETTINGS_JSON_SETTINGS" value="<%=Labels.JSON_SETTINGS%>"/>
<c:set var="HINT_AST_SETTINGS_JSON_SETTINGS" value="<%=Hints.JSON_SETTINGS%>"/>

<c:set var="AST_SETTINGS_JSON_POLICY" value="<%=Params.JSON_POLICY%>"/>
<c:set var="LABEL_AST_SETTINGS_JSON_POLICY" value="<%=Labels.JSON_POLICY%>"/>
<c:set var="HINT_AST_SETTINGS_JSON_POLICY" value="<%=Hints.JSON_POLICY%>"/>

<c:set var="AST_MODE" value="<%=Params.AST_MODE%>"/>
<c:set var="LABEL_AST_MODE" value="<%=Labels.AST_MODE%>"/>
<c:set var="HINT_AST_MODE" value="<%=Hints.AST_MODE%>"/>
<%-- AST mode combobox content --%>
<c:set var="AST_MODE_SYNC" value="<%=Constants.AST_MODE_SYNC%>"/>
<c:set var="LABEL_AST_MODE_SYNC" value="<%=Labels.AST_MODE_SYNC%>"/>
<c:set var="HINT_AST_MODE_SYNC" value="<%=Hints.AST_MODE_SYNC%>"/>
<c:set var="AST_MODE_ASYNC" value="<%=Constants.AST_MODE_ASYNC%>"/>
<c:set var="LABEL_AST_MODE_ASYNC" value="<%=Labels.AST_MODE_ASYNC%>"/>
<c:set var="HINT_AST_MODE_ASYNC" value="<%=Hints.AST_MODE_ASYNC%>"/>

<c:set var="LABEL_STEP_FAIL_CONDITIONS" value="<%=Labels.STEP_FAIL_CONDITIONS%>"/>

<c:set var="FAIL_IF_FAILED" value="<%=Params.FAIL_IF_FAILED%>"/>
<c:set var="LABEL_FAIL_IF_FAILED" value="<%=Labels.FAIL_IF_FAILED%>"/>
<c:set var="HINT_FAIL_IF_FAILED" value="<%=Hints.FAIL_IF_FAILED%>"/>

<c:set var="FAIL_IF_UNSTABLE" value="<%=Params.FAIL_IF_UNSTABLE%>"/>
<c:set var="LABEL_FAIL_IF_UNSTABLE" value="<%=Labels.FAIL_IF_UNSTABLE%>"/>
<c:set var="HINT_FAIL_IF_UNSTABLE" value="<%=Hints.FAIL_IF_UNSTABLE%>"/>


<c:set var="REPORTING_REPORT" value="<%=Params.REPORTING_REPORT%>"/>
<c:set var="LABEL_REPORTING_REPORT" value="<%=Labels.REPORTING_REPORT%>"/>
<c:set var="HINT_REPORTING_REPORT" value="<%=Hints.REPORTING_REPORT%>"/>

<c:set var="REPORTING_REPORT_FILE" value="<%=Params.REPORTING_REPORT_FILE%>"/>
<c:set var="LABEL_REPORTING_REPORT_FILE" value="<%=Labels.REPORTING_REPORT_FILE%>"/>
<c:set var="HINT_REPORTING_REPORT_FILE" value="<%=Hints.REPORTING_REPORT_FILE%>"/>

<c:set var="REPORTING_REPORT_TEMPLATE" value="<%=Params.REPORTING_REPORT_TEMPLATE%>"/>
<c:set var="LABEL_REPORTING_REPORT_TEMPLATE" value="<%=Labels.REPORTING_REPORT_TEMPLATE%>"/>
<c:set var="HINT_REPORTING_REPORT_TEMPLATE" value="<%=Hints.REPORTING_REPORT_TEMPLATE%>"/>

<c:set var="REPORTING_REPORT_FORMAT" value="<%=Params.REPORTING_REPORT_FORMAT%>"/>
<c:set var="LABEL_REPORTING_REPORT_FORMAT" value="<%=Labels.REPORTING_REPORT_FORMAT%>"/>
<c:set var="HINT_REPORTING_REPORT_FORMAT" value="<%=Hints.REPORTING_REPORT_FORMAT%>"/>
<%-- Valid report format values and labels --%>
<c:set var="REPORTING_REPORT_FORMAT_HTML" value="<%=Constants.REPORTING_REPORT_FORMAT_HTML%>"/>
<c:set var="LABEL_REPORTING_REPORT_FORMAT_HTML" value="<%=Labels.REPORTING_REPORT_FORMAT_HTML%>"/>
<c:set var="REPORTING_REPORT_FORMAT_PDF" value="<%=Constants.REPORTING_REPORT_FORMAT_PDF%>"/>
<c:set var="LABEL_REPORTING_REPORT_FORMAT_PDF" value="<%=Labels.REPORTING_REPORT_FORMAT_PDF%>"/>

<c:set var="REPORTING_REPORT_LOCALE" value="<%=Params.REPORTING_REPORT_LOCALE%>"/>
<c:set var="LABEL_REPORTING_REPORT_LOCALE" value="<%=Labels.REPORTING_REPORT_LOCALE%>"/>
<c:set var="HINT_REPORTING_REPORT_LOCALE" value="<%=Hints.REPORTING_REPORT_LOCALE%>"/>
<%-- Valid locale values and labels --%>
<c:set var="REPORTING_LOCALE_ENGLISH" value="<%=Constants.REPORTING_LOCALE_ENGLISH%>"/>
<c:set var="LABEL_REPORTING_LOCALE_ENGLISH" value="<%=Labels.REPORTING_LOCALE_ENGLISH%>"/>
<c:set var="REPORTING_LOCALE_RUSSIAN" value="<%=Constants.REPORTING_LOCALE_RUSSIAN%>"/>
<c:set var="LABEL_REPORTING_LOCALE_RUSSIAN" value="<%=Labels.REPORTING_LOCALE_RUSSIAN%>"/>

<c:set var="REPORTING_REPORT_FILTER" value="<%=Params.REPORTING_REPORT_FILTER%>"/>
<c:set var="LABEL_REPORTING_REPORT_FILTER" value="<%=Labels.REPORTING_REPORT_FILTER%>"/>
<c:set var="HINT_REPORTING_REPORT_FILTER" value="<%=Hints.REPORTING_REPORT_FILTER%>"/>


<c:set var="REPORTING_DATA" value="<%=Params.REPORTING_DATA%>"/>
<c:set var="LABEL_REPORTING_DATA" value="<%=Labels.REPORTING_DATA%>"/>
<c:set var="HINT_REPORTING_DATA" value="<%=Hints.REPORTING_DATA%>"/>

<c:set var="REPORTING_DATA_FILE" value="<%=Params.REPORTING_DATA_FILE%>"/>
<c:set var="LABEL_REPORTING_DATA_FILE" value="<%=Labels.REPORTING_DATA_FILE%>"/>
<c:set var="HINT_REPORTING_DATA_FILE" value="<%=Hints.REPORTING_DATA_FILE%>"/>

<c:set var="REPORTING_DATA_FORMAT" value="<%=Params.REPORTING_DATA_FORMAT%>"/>
<c:set var="LABEL_REPORTING_DATA_FORMAT" value="<%=Labels.REPORTING_DATA_FORMAT%>"/>
<c:set var="HINT_REPORTING_DATA_FORMAT" value="<%=Hints.REPORTING_DATA_FORMAT%>"/>
<%-- Valid data export format values and labels --%>
<c:set var="REPORTING_DATA_FORMAT_JSON" value="<%=Constants.REPORTING_DATA_FORMAT_JSON%>"/>
<c:set var="LABEL_REPORTING_DATA_FORMAT_JSON" value="<%=Labels.REPORTING_DATA_FORMAT_JSON%>"/>
<c:set var="REPORTING_DATA_FORMAT_XML" value="<%=Constants.REPORTING_DATA_FORMAT_XML%>"/>
<c:set var="LABEL_REPORTING_DATA_FORMAT_XML" value="<%=Labels.REPORTING_DATA_FORMAT_XML%>"/>

<c:set var="REPORTING_DATA_LOCALE" value="<%=Params.REPORTING_DATA_LOCALE%>"/>
<c:set var="LABEL_REPORTING_DATA_LOCALE" value="<%=Labels.REPORTING_DATA_LOCALE%>"/>
<c:set var="HINT_REPORTING_DATA_LOCALE" value="<%=Hints.REPORTING_DATA_LOCALE%>"/>

<c:set var="REPORTING_DATA_FILTER" value="<%=Params.REPORTING_DATA_FILTER%>"/>
<c:set var="LABEL_REPORTING_DATA_FILTER" value="<%=Labels.REPORTING_DATA_FILTER%>"/>
<c:set var="HINT_REPORTING_DATA_FILTER" value="<%=Hints.REPORTING_DATA_FILTER%>"/>


<c:set var="REPORTING_RAWDATA" value="<%=Params.REPORTING_RAWDATA%>"/>
<c:set var="LABEL_REPORTING_RAWDATA" value="<%=Labels.REPORTING_RAWDATA%>"/>
<c:set var="HINT_REPORTING_RAWDATA" value="<%=Hints.REPORTING_RAWDATA%>"/>

<c:set var="REPORTING_RAWDATA_FILE" value="<%=Params.REPORTING_RAWDATA_FILE%>"/>
<c:set var="LABEL_REPORTING_RAWDATA_FILE" value="<%=Labels.REPORTING_RAWDATA_FILE%>"/>
<c:set var="HINT_REPORTING_RAWDATA_FILE" value="<%=Hints.REPORTING_RAWDATA_FILE%>"/>


<c:set var="REPORTING_SARIF" value="<%=Params.REPORTING_SARIF%>"/>
<c:set var="LABEL_REPORTING_SARIF" value="<%=Labels.REPORTING_SARIF%>"/>
<c:set var="HINT_REPORTING_SARIF" value="<%=Hints.REPORTING_SARIF%>"/>

<c:set var="REPORTING_SARIF_FILE" value="<%=Params.REPORTING_SARIF_FILE%>"/>
<c:set var="LABEL_REPORTING_SARIF_FILE" value="<%=Labels.REPORTING_SARIF_FILE%>"/>
<c:set var="HINT_REPORTING_SARIF_FILE" value="<%=Hints.REPORTING_SARIF_FILE%>"/>


<c:set var="REPORTING_SONARGIIF" value="<%=Params.REPORTING_SONARGIIF%>"/>
<c:set var="LABEL_REPORTING_SONARGIIF" value="<%=Labels.REPORTING_SONARGIIF%>"/>
<c:set var="HINT_REPORTING_SONARGIIF" value="<%=Hints.REPORTING_SONARGIIF%>"/>

<c:set var="REPORTING_SONARGIIF_FILE" value="<%=Params.REPORTING_SONARGIIF_FILE%>"/>
<c:set var="LABEL_REPORTING_SONARGIIF_FILE" value="<%=Labels.REPORTING_SONARGIIF_FILE%>"/>
<c:set var="HINT_REPORTING_SONARGIIF_FILE" value="<%=Hints.REPORTING_SONARGIIF_FILE%>"/>


<c:set var="REPORTING_JSON" value="<%=Params.REPORTING_JSON%>"/>
<c:set var="LABEL_REPORTING_JSON" value="<%=Labels.REPORTING_JSON%>"/>
<c:set var="HINT_REPORTING_JSON" value="<%=Hints.REPORTING_JSON%>"/>

<c:set var="REPORTING_JSON_SETTINGS" value="<%=Params.REPORTING_JSON_SETTINGS%>"/>
<c:set var="LABEL_REPORTING_JSON_SETTINGS" value="<%=Labels.REPORTING_JSON_SETTINGS%>"/>
<c:set var="HINT_REPORTING_JSON_SETTINGS" value="<%=Hints.REPORTING_JSON_SETTINGS%>"/>


<c:set var="FULL_SCAN_MODE" value="<%=Params.FULL_SCAN_MODE%>"/>
<c:set var="LABEL_FULL_SCAN_MODE" value="<%=Labels.FULL_SCAN_MODE%>"/>
<c:set var="HINT_FULL_SCAN_MODE" value="<%=Hints.FULL_SCAN_MODE%>"/>

<c:set var="VERBOSE" value="<%=Params.VERBOSE%>"/>
<c:set var="LABEL_VERBOSE" value="<%=Labels.VERBOSE%>"/>
<c:set var="HINT_VERBOSE" value="<%=Hints.VERBOSE%>"/>

<c:set var="INCLUDES" value="<%=Params.INCLUDES%>"/>
<c:set var="LABEL_INCLUDES" value="<%=Labels.INCLUDES%>"/>
<c:set var="HINT_INCLUDES" value="<%=Hints.INCLUDES%>"/>

<c:set var="REMOVE_PREFIX" value="<%=Params.REMOVE_PREFIX%>"/>
<c:set var="LABEL_REMOVE_PREFIX" value="<%=Labels.REMOVE_PREFIX%>"/>
<c:set var="HINT_REMOVE_PREFIX" value="<%=Hints.REMOVE_PREFIX%>"/>

<c:set var="EXCLUDES" value="<%=Params.EXCLUDES%>"/>
<c:set var="LABEL_EXCLUDES" value="<%=Labels.EXCLUDES%>"/>
<c:set var="HINT_EXCLUDES" value="<%=Hints.EXCLUDES%>"/>

<c:set var="PATTERN_SEPARATOR" value="<%=Params.PATTERN_SEPARATOR%>"/>
<c:set var="LABEL_PATTERN_SEPARATOR" value="<%=Labels.PATTERN_SEPARATOR%>"/>
<c:set var="HINT_PATTERN_SEPARATOR" value="<%=Hints.PATTERN_SEPARATOR%>"/>

<c:set var="USE_DEFAULT_EXCLUDES" value="<%=Params.USE_DEFAULT_EXCLUDES%>"/>
<c:set var="LABEL_USE_DEFAULT_EXCLUDES" value="<%=Labels.USE_DEFAULT_EXCLUDES%>"/>
<c:set var="HINT_USE_DEFAULT_EXCLUDES" value="<%=Hints.USE_DEFAULT_EXCLUDES%>"/>

<c:set var="FLATTEN" value="<%=Params.FLATTEN%>"/>
<c:set var="LABEL_FLATTEN" value="<%=Labels.FLATTEN%>"/>
<c:set var="HINT_FLATTEN" value="<%=Hints.FLATTEN%>"/>

<c:set var="ADMIN_CONTROLLER_PATH" value="<%=Constants.ADMIN_CONTROLLER_PATH%>"/>
<c:set var="TEST_CONTROLLER_PATH" value="<%=Constants.AST_CONTROLLER_PATH%>"/>

