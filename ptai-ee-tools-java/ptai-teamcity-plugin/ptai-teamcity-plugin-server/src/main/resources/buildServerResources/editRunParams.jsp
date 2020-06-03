<%@ taglib prefix="props" tagdir="/WEB-INF/tags/props" %>
<%@ taglib prefix="l" tagdir="/WEB-INF/tags/layout" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="bs" tagdir="/WEB-INF/tags" %>
<%--
<%@ taglib prefix="admin" tagdir="/WEB-INF/tags/admin" %>
<script type="text/javascript" src="<c:url value='${teamcityPluginResourcesPath}testConnection.js'/>"></script>
--%>
<jsp:useBean id="optionsBean" class="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstOptionsBean"/>
<jsp:useBean id="propertiesBean" scope="request" type="jetbrains.buildServer.controllers.BasePropertiesBean"/>

<%@include file="constants.jsp" %>

<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels"%>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Hints"%>


<%--
<style>
    #cxPresetId, #cxTeamId {
        width: 535px;
    }

    .scanControlSectionTable {
        margin-left: -10px;
    }

    .runnerFormTable .cx-title.groupingTitle td {
        padding: 6px 0 6px 8px;
        background-color: #edeff5;
        font-weight: bold;
        font-size: 16px;
    }

</style>

${'true'.equals(cxUseDefaultServer) ?
optionsBean.testConnection(cxGlobalServerUrl, cxGlobalUsername, cxGlobalPassword) :
optionsBean.testConnection(cxServerUrl, cxUsername, cxPassword)}


<c:if test="${propertiesBean.properties[optionsBean.useDefaultServer] == 'true'}">
    <c:set var="hideServerOverrideSection" value="${optionsBean.noDisplay}"/>
</c:if>

<c:if test="${propertiesBean.properties[optionsBean.useDefaultSastConfig] == 'true'}">
    <c:set var="hideSastConfigSection" value="${optionsBean.noDisplay}"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.sastEnabled] != 'true'}">
    <c:set var="hideCxSast" value="${optionsBean.noDisplay}"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.useDefaultSastConfig] != 'true'}">
    <c:set var="hideDefaultSastConfigSection" value="${optionsBean.noDisplay}"/>
</c:if>

<c:if test="${propertiesBean.properties[optionsBean.globalIsSynchronous] == 'true'}">
    <c:set var="globalIsSynchronus" value="true"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.globalIsSynchronous] != 'true'}">
    <c:set var="globalIsSynchronus" value="false"/>
</c:if>

<c:if test="${propertiesBean.properties[optionsBean.globalThresholdEnabled] == 'true'}">
    <c:set var="globalThresholdEnabled" value="true"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.globalThresholdEnabled] != 'true'}">
    <c:set var="globalThresholdEnabled" value="false"/>
</c:if>

<c:if test="${propertiesBean.properties[optionsBean.globalProjectPolicyViolation] == 'true'}">
    <c:set var="globalProjectPolicydEnabled" value="true"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.globalProjectPolicyViolation] != 'true'}">
    <c:set var="globalProjectPolicydEnabled" value="false"/>
</c:if>

<c:if test="${propertiesBean.properties[optionsBean.globalOsaThresholdEnabled] == 'true'}">
    <c:set var="globalOsaThresholdEnabled" value="true"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.globalOsaThresholdEnabled] != 'true'}">
    <c:set var="globalOsaThresholdEnabled" value="false"/>
</c:if>

<c:if test="${propertiesBean.properties[optionsBean.useDefaultScanControl] == 'true'}">
    <c:set var="hideSpecificScanControlSection" value="${optionsBean.noDisplay}"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.useDefaultScanControl] != 'true'}">
    <c:set var="hideDefaultScanControlSection" value="${optionsBean.noDisplay}"/>
</c:if>

<c:if test="${propertiesBean.properties[optionsBean.isSynchronous] != 'true'}">
    <c:set var="hideScanControlSection" value="${optionsBean.noDisplay}"/>
</c:if>

<c:if test="${propertiesBean.properties[optionsBean.thresholdEnabled] != 'true' }">
    <c:set var="hideThresholdSection" value="${optionsBean.noDisplay}"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.osaEnabled] != 'true'}">
    <c:set var="hideOsaSection" value="${optionsBean.noDisplay}"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.osaThresholdEnabled] != 'true'}">
    <c:set var="hideOsaThresholdSection" value="${optionsBean.noDisplay}"/>
</c:if>
--%>

<c:if test="${propertiesBean.properties[optionsBean.ptaiScanSettings] == SCAN_SETTINGS_UI}">
    <c:set var="hideUi" value=""/>
    <c:set var="hideJson" value="style='display:none'"/>
</c:if>
<c:if test="${propertiesBean.properties[optionsBean.ptaiScanSettings] == SCAN_SETTINGS_JSON}">
    <c:set var="hideUi" value="style='display:none'"/>
    <c:set var="hideJson" value=""/>
</c:if>


<l:settingsGroup className="ai-title" title="PT AI vulnerability analysis">
    <tr>
        <th>
            <label for="${optionsBean.ptaiScanSettings}">${LABEL_SCAN_SETTINGS}</label></th>
        <td>
            <c:set var="onchange">
                var sel = $('${optionsBean.ptaiScanSettings}');
                var settingsMode = sel[sel.selectedIndex].value;
                if ('${SCAN_SETTINGS_JSON}' == settingsMode) {
                    BS.Util.show('${optionsBean.ptaiJsonSettings}Container');
                    BS.Util.show('${optionsBean.ptaiJsonPolicy}Container');
                    BS.Util.hide('${optionsBean.ptaiProjectName}Container');
                } else if ('${SCAN_SETTINGS_UI}' == settingsMode) {
                    BS.Util.hide('${optionsBean.ptaiJsonSettings}Container');
                    BS.Util.hide('${optionsBean.ptaiJsonPolicy}Container');
                    BS.Util.show('${optionsBean.ptaiProjectName}Container');
                }
                BS.VisibilityHandlers.updateVisibility('mainContent');
            </c:set>
            <props:selectProperty
                    name="${optionsBean.ptaiScanSettings}"
                    className="mediumField" onchange="${onchange}">
                <props:option value="${SCAN_SETTINGS_UI}" currValue="${propertiesBean.properties[optionsBean.ptaiScanSettings]}">${HINT_SCAN_SETTINGS_UI}</props:option>
                <props:option value="${SCAN_SETTINGS_JSON}" currValue="${propertiesBean.properties[optionsBean.ptaiScanSettings]}">${HINT_SCAN_SETTINGS_JSON}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_SCAN_SETTINGS}</span>
        </td>
    </tr>

    <tr id="${optionsBean.ptaiProjectName}Container" ${hideUi}>
        <th>
            <label for="${optionsBean.ptaiProjectName}">${LABEL_PROJECT_NAME}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${optionsBean.ptaiProjectName}" className="longField"/>
            <span class="smallNote">${HINT_PROJECT_NAME}</span>
            <span class="error" id="${optionsBean.ptaiProjectName}Error"></span>
        </td>
    </tr>

    <tr id="${optionsBean.ptaiJsonSettings}Container" ${hideJson}>
        <th>
            <label for="${optionsBean.ptaiJsonSettings}">${LABEL_JSON_SETTINGS}<l:star/></label>
        </th>
        <td>
            <props:multilineProperty
                    name="${optionsBean.ptaiJsonSettings}"
                    className="longField"
                    linkTitle="Edit JSON settings"
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_JSON_SETTINGS}"/>
            <span class="error" id="${optionsBean.ptaiJsonSettings}Error"></span>
        </td>
    </tr>
    <tr id="${optionsBean.ptaiJsonPolicy}Container" ${hideJson}>
        <th>
            <label for="${optionsBean.ptaiJsonPolicy}">${LABEL_JSON_POLICY}</label>
        </th>
        <td>
            <props:multilineProperty
                name="${optionsBean.ptaiJsonPolicy}"
                className="longField"
                linkTitle="Edit JSON policy"
                rows="3"
                cols="49"
                expanded="${true}"
                note="${HINT_JSON_POLICY}"/>
            <span class="error" id="${optionsBean.ptaiJsonPolicy}Error"></span>
        </td>
    </tr>

    <tr>
        <th>
            <label>${LABEL_STEP_FAIL_CONDITIONS}</label>
        </th>
        <td>
            <props:checkboxProperty name="${optionsBean.ptaiFailIfFailed}"/>
            <label for="${optionsBean.ptaiFailIfFailed}">${LABEL_FAIL_IF_FAILED}</label>
            <span class="smallNote">${HINT_FAIL_IF_FAILED}</span>
            <br>
            <props:checkboxProperty name="${optionsBean.ptaiFailIfUnstable}"/>
            <label for="${optionsBean.ptaiFailIfUnstable}">${LABEL_FAIL_IF_UNSTABLE}</label>
            <span class="smallNote">${HINT_FAIL_IF_UNSTABLE}</span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${optionsBean.ptaiNodeName}">${LABEL_NODE_NAME}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${optionsBean.ptaiNodeName}" className="longField"/>
            <span class="smallNote">${HINT_NODE_NAME}</span>
            <span class="error" id="${optionsBean.ptaiNodeName}Error"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${optionsBean.ptaiVerbose}">${LABEL_VERBOSE}</label>
        </th>
        <td>
            <props:checkboxProperty name="${optionsBean.ptaiVerbose}"/>
            <span class="smallNote">${HINT_VERBOSE}</span>
        </td>
    </tr>

    <tr>
        <th>
            <label for="${optionsBean.ptaiIncludes}">${LABEL_INCLUDES}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${optionsBean.ptaiIncludes}" className="longField"/>
            <span class="smallNote">${HINT_INCLUDES}</span>
            <span class="error" id="${optionsBean.ptaiIncludes}Error"></span>
        </td>
    </tr>

    <tr>
        <th>
            <label for="${optionsBean.ptaiExcludes}">${LABEL_EXCLUDES}</label>
        </th>
        <td>
            <props:textProperty name="${optionsBean.ptaiExcludes}" className="longField"/>
            <span class="smallNote">${HINT_EXCLUDES}</span>
            <span class="error" id="${optionsBean.ptaiExcludes}Error"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${optionsBean.ptaiRemovePrefix}">${LABEL_REMOVE_PREFIX}</label>
        </th>
        <td>
            <props:textProperty name="${optionsBean.ptaiRemovePrefix}" className="longField"/>
            <span class="smallNote">${HINT_REMOVE_PREFIX}</span>
            <span class="error" id="${optionsBean.ptaiRemovePrefix}Error"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${optionsBean.ptaiPatternSeparator}">${LABEL_PATTERN_SEPARATOR}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${optionsBean.ptaiPatternSeparator}" className="longField"/>
            <span class="smallNote">${HINT_PATTERN_SEPARATOR}</span>
            <span class="error" id="${optionsBean.ptaiPatternSeparator}Error"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${optionsBean.ptaiUseDefaultExcludes}">${LABEL_USE_DEFAULT_EXCLUDES}</label>
        </th>
        <td>
            <props:checkboxProperty name="${optionsBean.ptaiUseDefaultExcludes}"/>
            <span class="smallNote">${HINT_USE_DEFAULT_EXCLUDES}</span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${optionsBean.ptaiFlatten}">${LABEL_FLATTEN}</label>
        </th>
        <td>
            <props:checkboxProperty name="${optionsBean.ptaiFlatten}"/>
            <span class="smallNote">${HINT_FLATTEN}</span>
        </td>
    </tr>
</l:settingsGroup>
