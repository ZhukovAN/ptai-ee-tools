<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Hints" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params" %>

<c:set var="URL" value="<%=Params.URL%>"/>
<c:set var="LABEL_URL" value="<%=Labels.URL%>"/>
<c:set var="HINT_URL" value="<%=Hints.URL%>"/>

<c:set var="TOKEN" value="<%=Params.TOKEN%>"/>
<c:set var="LABEL_TOKEN" value="<%=Labels.TOKEN%>"/>
<c:set var="HINT_TOKEN" value="<%=Hints.TOKEN%>"/>

<c:set var="CERTIFICATES" value="<%=Params.CERTIFICATES%>"/>
<c:set var="LABEL_CERTIFICATES" value="<%=Labels.CERTIFICATES%>"/>
<c:set var="HINT_CERTIFICATES" value="<%=Hints.CERTIFICATES%>"/>

<c:set var="INSECURE" value="<%=Params.INSECURE%>"/>
<c:set var="LABEL_INSECURE" value="<%=Labels.INSECURE%>"/>
<c:set var="HINT_INSECURE" value="<%=Hints.INSECURE%>"/>

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

<c:set var="AST_SETTINGS" value="<%=Params.AST_SETTINGS%>"/>
<c:set var="LABEL_AST_SETTINGS" value="<%=Labels.AST_SETTINGS%>"/>
<c:set var="HINT_AST_SETTINGS" value="<%=Hints.AST_SETTINGS%>"/>
<%-- Scan settings combobox content --%>
<c:set var="LABEL_AST_SETTINGS_UI" value="<%=Labels.AST_SETTINGS_UI%>"/>
<c:set var="HINT_AST_SETTINGS_UI" value="<%=Hints.AST_SETTINGS_UI%>"/>
<c:set var="AST_SETTINGS_UI" value="<%=Constants.AST_SETTINGS_UI%>"/>
<c:set var="LABEL_AST_SETTINGS_JSON" value="<%=Labels.AST_SETTINGS_JSON%>"/>
<c:set var="HINT_AST_SETTINGS_JSON" value="<%=Hints.AST_SETTINGS_JSON%>"/>
<c:set var="AST_SETTINGS_JSON" value="<%=Constants.AST_SETTINGS_JSON%>"/>

<c:set var="PROJECT_NAME" value="<%=Params.PROJECT_NAME%>"/>
<c:set var="LABEL_PROJECT_NAME" value="<%=Labels.PROJECT_NAME%>"/>
<c:set var="HINT_PROJECT_NAME" value="<%=Hints.PROJECT_NAME%>"/>

<c:set var="JSON_SETTINGS" value="<%=Params.JSON_SETTINGS%>"/>
<c:set var="LABEL_JSON_SETTINGS" value="<%=Labels.JSON_SETTINGS%>"/>
<c:set var="HINT_JSON_SETTINGS" value="<%=Hints.JSON_SETTINGS%>"/>

<c:set var="JSON_POLICY" value="<%=Params.JSON_POLICY%>"/>
<c:set var="LABEL_JSON_POLICY" value="<%=Labels.JSON_POLICY%>"/>
<c:set var="HINT_JSON_POLICY" value="<%=Hints.JSON_POLICY%>"/>

<c:set var="LABEL_STEP_FAIL_CONDITIONS" value="<%=Labels.STEP_FAIL_CONDITIONS%>"/>

<c:set var="FAIL_IF_FAILED" value="<%=Params.FAIL_IF_FAILED%>"/>
<c:set var="LABEL_FAIL_IF_FAILED" value="<%=Labels.FAIL_IF_FAILED%>"/>
<c:set var="HINT_FAIL_IF_FAILED" value="<%=Hints.FAIL_IF_FAILED%>"/>

<c:set var="FAIL_IF_UNSTABLE" value="<%=Params.FAIL_IF_UNSTABLE%>"/>
<c:set var="LABEL_FAIL_IF_UNSTABLE" value="<%=Labels.FAIL_IF_UNSTABLE%>"/>
<c:set var="HINT_FAIL_IF_UNSTABLE" value="<%=Hints.FAIL_IF_UNSTABLE%>"/>

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

<c:set var="REPORT_SETTINGS" value="<%=Params.REPORT_SETTINGS%>"/>
<c:set var="LABEL_REPORT_SETTINGS" value="<%=Labels.REPORT_SETTINGS%>"/>
<c:set var="HINT_REPORT_SETTINGS" value="<%=Hints.REPORT_SETTINGS%>"/>

<c:set var="REPORT_SETTINGS_NONE" value="<%=Constants.REPORT_SETTINGS_NONE%>"/>
<c:set var="LABEL_REPORT_SETTINGS_NONE" value="<%=Labels.REPORT_SETTINGS_NONE%>"/>
<c:set var="HINT_REPORT_SETTINGS_NONE" value="<%=Hints.REPORT_SETTINGS_NONE%>"/>

<c:set var="REPORT_SETTINGS_SINGLE" value="<%=Constants.REPORT_SETTINGS_SINGLE%>"/>
<c:set var="LABEL_REPORT_SETTINGS_SINGLE" value="<%=Labels.REPORT_SETTINGS_SINGLE%>"/>
<c:set var="HINT_REPORT_SETTINGS_SINGLE" value="<%=Hints.REPORT_SETTINGS_SINGLE%>"/>

<c:set var="REPORT_SETTINGS_JSON" value="<%=Constants.REPORT_SETTINGS_JSON%>"/>
<c:set var="LABEL_REPORT_SETTINGS_JSON" value="<%=Labels.REPORT_JSON%>"/>
<c:set var="HINT_REPORT_SETTINGS_JSON" value="<%=Hints.REPORT_JSON%>"/>

<c:set var="REPORT_TEMPLATE_NAME" value="<%=Params.REPORT_TEMPLATE_NAME%>"/>
<c:set var="LABEL_REPORT_TEMPLATE_NAME" value="<%=Labels.REPORT_TEMPLATE_NAME%>"/>
<c:set var="HINT_REPORT_TEMPLATE_NAME" value="<%=Hints.REPORT_TEMPLATE_NAME%>"/>

<c:set var="REPORT_FORMAT" value="<%=Params.REPORT_FORMAT%>"/>
<c:set var="LABEL_REPORT_FORMAT" value="<%=Labels.REPORT_FORMAT%>"/>
<c:set var="HINT_REPORT_FORMAT" value="<%=Hints.REPORT_FORMAT%>"/>

<c:set var="REPORT_LOCALE" value="<%=Params.REPORT_LOCALE%>"/>
<c:set var="LABEL_REPORT_LOCALE" value="<%=Labels.REPORT_LOCALE%>"/>
<c:set var="HINT_REPORT_LOCALE" value="<%=Hints.REPORT_LOCALE%>"/>

<c:set var="REPORT_JSON" value="<%=Params.REPORT_JSON%>"/>
<c:set var="LABEL_REPORT_JSON" value="<%=Labels.REPORT_JSON%>"/>
<c:set var="HINT_REPORT_JSON" value="<%=Hints.REPORT_JSON%>"/>

<c:set var="ADMIN_CONTROLLER_PATH" value="<%=Constants.ADMIN_CONTROLLER_PATH%>"/>
<c:set var="TEST_CONTROLLER_PATH" value="<%=Constants.TEST_CONTROLLER_PATH%>"/>

