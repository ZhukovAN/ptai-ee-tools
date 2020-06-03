<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels"%>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Hints"%>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants"%>

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<c:set var="LABEL_SCAN_SETTINGS" value="<%=Labels.SCAN_SETTINGS%>"/>
<c:set var="LABEL_PROJECT_NAME" value="<%=Labels.PROJECT_NAME%>"/>
<c:set var="LABEL_JSON_SETTINGS" value="<%=Labels.JSON_SETTINGS%>"/>
<c:set var="LABEL_JSON_POLICY" value="<%=Labels.JSON_POLICY%>"/>
<c:set var="LABEL_FAIL_IF_FAILED" value="<%=Labels.FAIL_IF_FAILED%>"/>
<c:set var="LABEL_FAIL_IF_UNSTABLE" value="<%=Labels.FAIL_IF_UNSTABLE%>"/>
<c:set var="LABEL_NODE_NAME" value="<%=Labels.NODE_NAME%>"/>
<c:set var="LABEL_VERBOSE" value="<%=Labels.VERBOSE%>"/>
<c:set var="LABEL_INCLUDES" value="<%=Labels.INCLUDES%>"/>
<c:set var="LABEL_REMOVE_PREFIX" value="<%=Labels.REMOVE_PREFIX%>"/>
<c:set var="LABEL_EXCLUDES" value="<%=Labels.EXCLUDES%>"/>
<c:set var="LABEL_PATTERN_SEPARATOR" value="<%=Labels.PATTERN_SEPARATOR%>"/>
<c:set var="LABEL_USE_DEFAULT_EXCLUDES" value="<%=Labels.USE_DEFAULT_EXCLUDES%>"/>
<c:set var="LABEL_FLATTEN" value="<%=Labels.FLATTEN%>"/>

<c:set var="SCAN_SETTINGS_JSON" value="<%=Constants.SETTINGS_JSON%>"/>
<c:set var="SCAN_SETTINGS_UI" value="<%=Constants.SETTINGS_UI%>"/>
<c:set var="HINT_SCAN_SETTINGS_JSON" value="<%=Hints.SETTINGS_JSON%>"/>
<c:set var="HINT_SCAN_SETTINGS_UI" value="<%=Hints.SETTINGS_UI%>"/>
<c:set var="LABEL_STEP_FAIL_CONDITIONS" value="<%=Labels.STEP_FAIL_CONDITIONS%>"/>

<c:set var="HINT_SCAN_SETTINGS" value="<%=Hints.SCAN_SETTINGS%>"/>
<c:set var="HINT_PROJECT_NAME" value="<%=Hints.PROJECT_NAME%>"/>
<c:set var="HINT_JSON_SETTINGS" value="<%=Hints.JSON_SETTINGS%>"/>
<c:set var="HINT_JSON_POLICY" value="<%=Hints.JSON_POLICY%>"/>
<c:set var="HINT_FAIL_IF_FAILED" value="<%=Hints.FAIL_IF_FAILED%>"/>
<c:set var="HINT_FAIL_IF_UNSTABLE" value="<%=Hints.FAIL_IF_UNSTABLE%>"/>
<c:set var="HINT_NODE_NAME" value="<%=Hints.NODE_NAME%>"/>
<c:set var="HINT_VERBOSE" value="<%=Hints.VERBOSE%>"/>
<c:set var="HINT_INCLUDES" value="<%=Hints.INCLUDES%>"/>
<c:set var="HINT_REMOVE_PREFIX" value="<%=Hints.REMOVE_PREFIX%>"/>
<c:set var="HINT_EXCLUDES" value="<%=Hints.EXCLUDES%>"/>
<c:set var="HINT_PATTERN_SEPARATOR" value="<%=Hints.PATTERN_SEPARATOR%>"/>
<c:set var="HINT_USE_DEFAULT_EXCLUDES" value="<%=Hints.USE_DEFAULT_EXCLUDES%>"/>
<c:set var="HINT_FLATTEN" value="<%=Hints.FLATTEN%>"/>
