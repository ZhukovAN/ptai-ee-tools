<%@ include file="common.jsp" %>
<%@ include file="constants.jsp" %>

<bs:linkCSS dynamic="${true}">
    /css/admin/adminMain.css
    /css/admin/serverConfig.css
    ${teamcityPluginResourcesPath}css/ptai.css
</bs:linkCSS>

<bs:linkScript>
    <%-- TeamCity comes with few built-in options we can utilize to enhance
    the user experience during the test connection. For example, displaying a
    progress bar and a nice pop-up message once the test passes or fails.--%>
    /js/bs/testConnection.js
    <%-- In order to utilize the built-in test javascript functionality
    that comes with TeamCity, we implemented ptai.js. This file extends
    the base form behavior in TeamCity and registers to TeamCity form events --%>
    ${teamcityPluginResourcesPath}js/ptai.js
</bs:linkScript>

<script type="text/javascript">
    $j(function() {
        PtaiConnectionSettingsForm.setupEventHandlers();

        $('${SERVER_SETTINGS_GLOBAL_TOKEN}').getEncryptedPassword = function(pubKey) {
            let initialValueField = $("prop:encrypted:${SERVER_SETTINGS_GLOBAL_TOKEN}");
            let initialValue = (initialValueField && initialValueField.value && initialValueField.value.length > 0) ? initialValueField.value : '';
            window.console.log('Initial value length ' + initialValue.length);
            if (0 === initialValue.length)
                initialValue = BS.Encrypt.encryptData(this.value, pubKey);
            window.console.log('Sending initial value ' + initialValue);
            return initialValue;
        };
        window.console.log('getEncryptedPassword is set up');
    });
</script>

<jsp:useBean id="propertiesBean" scope="request" type="jetbrains.buildServer.controllers.BasePropertiesBean"/>

<div id="settingsContainer">
    <form id="adminForm" action="<c:url value='${ADMIN_CONTROLLER_PATH}'/>"
          method="post"
          onsubmit="return PtaiConnectionSettingsForm.save()">

        <table class="runnerFormTable">
            <tr class="groupingTitle">
                <td colspan="2">PT AI server</td>
            </tr>

            <tbody class="ptai-group">

                <tr>
                    <th>
                        <label for="${SERVER_SETTINGS_GLOBAL_URL}">${LABEL_SERVER_SETTINGS_GLOBAL_URL}<l:star/></label>
                    </th>
                    <td>
                        <props:textProperty name="${SERVER_SETTINGS_GLOBAL_URL}" className="longField"/>
                        <span class="smallNote">${HINT_SERVER_SETTINGS_GLOBAL_URL}</span>
                        <span class="error" id="error_${SERVER_SETTINGS_GLOBAL_URL}"></span>
                    </td>
                </tr>

                <tr>
                    <th>
                        <label for="${SERVER_SETTINGS_GLOBAL_TOKEN}">${LABEL_SERVER_SETTINGS_GLOBAL_TOKEN}<l:star/></label>
                    </th>
                    <td>
                        <props:passwordProperty name="${SERVER_SETTINGS_GLOBAL_TOKEN}" className="longField"/>
                        <span class="smallNote">${HINT_SERVER_SETTINGS_GLOBAL_TOKEN}</span>
                        <span class="error" id="error_${SERVER_SETTINGS_GLOBAL_TOKEN}"></span>
                    </td>
                </tr>

                <tr>
                    <th>
                        <label for="${SERVER_SETTINGS_GLOBAL_CERTIFICATES}">${LABEL_SERVER_SETTINGS_GLOBAL_CERTIFICATES}</label>
                    </th>
                    <td>
                        <props:multilineProperty
                                name="${SERVER_SETTINGS_GLOBAL_CERTIFICATES}"
                                className="longField"
                                linkTitle="Trust these CA certificates"
                                rows="3" cols="49" expanded="${true}"
                                note="${HINT_SERVER_SETTINGS_GLOBAL_CERTIFICATES}"/>
                        <span class="error" id="error_${SERVER_SETTINGS_GLOBAL_CERTIFICATES}"></span>
                    </td>
                </tr>
                <tr>
                    <th>
                        <label for="${SERVER_SETTINGS_GLOBAL_INSECURE}">${LABEL_SERVER_SETTINGS_GLOBAL_INSECURE}</label>
                    </th>
                    <td>
                        <props:checkboxProperty name="${SERVER_SETTINGS_GLOBAL_INSECURE}"/>
						<span class="smallNote">${HINT_SERVER_SETTINGS_GLOBAL_INSECURE}</span>
                        <span class="error" id="error_${SERVER_SETTINGS_GLOBAL_INSECURE}"></span>
                    </td>
                </tr>
			
            </tbody>
        </table>

        <div class="saveButtonsBlock">
            <forms:submit type="submit" label="Save" />
            <forms:submit id="test" type="button" label="<%=Labels.TEST%>"/>
            <input type="hidden" id="mode" name="mode" value="modify"/>
            <input type="hidden" id="publicKey" name="publicKey" value="<c:out value='${hexEncodedPublicKey}'/>"/>
            <forms:saving/>
        </div>
    </form>
    <%-- testConnectionDialog, testConnectionStatus and testConnectionDetails are
     identifiers that are hardcoded in checkConnectionSettings.js --%>
    <bs:dialog dialogId="testConnectionDialog"
               title="Test PT AI server connection"
               closeCommand="BS.TestConnectionDialog.close();"
               closeAttrs="showdiscardchangesmessage='false'">
        <div id="testConnectionStatus"></div>
        <div id="testConnectionDetails" class="mono"></div>
    </bs:dialog>
    <forms:modified/>
</div>

