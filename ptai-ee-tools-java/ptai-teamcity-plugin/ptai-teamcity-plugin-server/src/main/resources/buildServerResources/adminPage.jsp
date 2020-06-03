<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@include file="/include.jsp" %>

<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels" %>
<%@ page import="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Hints" %>
<c:set var="CONFIG_GLOBAL" value="<%=Constants.CONTROLLER_PATH%>"/>

<%--
<bs:linkCSS dynamic="${true}">
    /css/admin/adminMain.css
    /css/admin/serverConfig.css
</bs:linkCSS>
--%>

<bs:linkScript>
    <%-- TeamCity comes with few built-in options we can utilize to enhance
    the user experience during the test connection. For example, displaying a
    progress bar and a nice pop-up message once the test passes or fails.--%>
    /js/bs/testConnection.js
    <%-- In order to utilize the built-in test javascript functionality
    that comes with TeamCity, we implemented ptaiSettings.js. This file extends
    the base form behavior in TeamCity and registers to TeamCity form events --%>
    ${teamcityPluginResourcesPath}js/ptaiSettings.js
</bs:linkScript>

<script type="text/javascript">
    $j(function() {
        PtaiAdmin.SettingsForm.setupEventHandlers();
    });
</script>

<jsp:useBean id="settingsBean"
             scope="request"
             type="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettingsBean"/>

<div id="settingsContainer">
    <form id="adminForm" action="<c:url value='<%=Constants.CONTROLLER_PATH%>'/>" method="post" onsubmit="return PtaiAdmin.SettingsForm.storeToFile()">

        <table class="runnerFormTable">
            <tr class="groupingTitle">
                <td colspan="2">PT AI server</td>
            </tr>

            <tr>
                <th><label for="<%=Params.GLOBAL_URL%>"><%=Labels.GLOBAL_URL%><l:star/></label></th>
                <td>
                    <forms:textField name="<%=Params.GLOBAL_URL%>" value="${settingsBean.ptaiGlobalUrl}" className="longField"/>
                    <span class="smallNote"><%=Hints.GLOBAL_URL%></span>
                    <span class="error" id="<%=Params.GLOBAL_URL + "Error"%>"></span>
                </td>
            </tr>
            <tr>
                <th><label for="<%=Params.GLOBAL_USER%>"><%=Labels.GLOBAL_USER%><l:star/></label></th>
                <td>
                    <forms:textField name="<%=Params.GLOBAL_USER%>" value="${settingsBean.ptaiGlobalUser}" className="longField"/>
                    <span class="smallNote"><%=Hints.GLOBAL_USER%></span>
                    <span class="error" id="<%=Params.GLOBAL_USER + "Error"%>"></span>
                </td>
            </tr>

            <tr>
                <th><label for="<%=Params.GLOBAL_TOKEN%>"><%=Labels.GLOBAL_TOKEN%><l:star/></label></th>
                <td>
                    <input type="password" id="<%=Params.GLOBAL_TOKEN%>" name="<%=Params.GLOBAL_TOKEN%>" value="${settingsBean.ptaiGlobalToken}" class="longField"/>
                    <span class="smallNote"><%=Hints.GLOBAL_TOKEN%></span>
                    <span class="error" id="<%=Params.GLOBAL_TOKEN + "Error"%>"></span>
                </td>
            </tr>

            <tr>
                <th><label for="<%=Params.GLOBAL_TRUSTED_CERTIFICATES%>"><%=Labels.GLOBAL_TRUSTED_CERTIFICATES%></label></th>
                <td>
                    <textarea name="<%=Params.GLOBAL_TRUSTED_CERTIFICATES%>" id="<%=Params.GLOBAL_TRUSTED_CERTIFICATES%>" rows="5" cols="50" wrap="off" className="longField">${settingsBean.ptaiGlobalTrustedCertificates}</textarea>
                    <span class="smallNote"><%=Hints.GLOBAL_TRUSTED_CERTIFICATES%></span>
                    <span class="error" id="<%=Params.GLOBAL_TRUSTED_CERTIFICATES + "Error"%>"></span>
                </td>
            </tr>
        </table>

        <div class="saveButtonsBlock">
            <forms:submit type="submit" label="Save" />
            <forms:submit id="test" type="button" label="<%=Labels.TEST%>"/>
            <input type="hidden" id="submitMode" name="submitMode" value="storeToFile"/>
            <input type="hidden" id="publicKey" name="publicKey" value="<c:out value='${settingsBean.hexEncodedPublicKey}'/>"/>
            <forms:saving/>
        </div>
    </form>
    <%-- testConnectionDialog, testConnectionStatus and testConnectionDetails are
     identifiers that are hardcoded in testConnection.js --%>
    <bs:dialog dialogId="testConnectionDialog"
               title="Test PT AI server connection"
               closeCommand="BS.TestConnectionDialog.close();"
               closeAttrs="showdiscardchangesmessage='false'">
        <div id="testConnectionStatus"></div>
        <div id="testConnectionDetails" class="mono"></div>
    </bs:dialog>
    <forms:modified/>
</div>

