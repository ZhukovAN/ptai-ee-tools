<%@ include file="common.jsp" %>
<%@ include file="constants.jsp" %>

<%-- During first adding new build step TeamCity loads plugin's RunType JSP form
 using BS.ajaxUpdater in admin/editRunType.jsp file. This AJAX request doesn't
 load JavaScripts Scripts included as <script src=... > in the body of the
 page (see https://teamcity-support.jetbrains.com/hc/en-us/community/posts/206690595-Javascript-not-loaded-the-first-time-a-new-build-runner-is-added).
 That means that we need to inject these scripts directly to page. And to avoid
 code duplication (as these scripts may be used somwhere else, i.e. in administrative
 page) we'll download these scripts and stylesheets on page load complete --%>

<style id="ptaicss"></style>

<jsp:useBean id="propertiesBean" scope="request" type="jetbrains.buildServer.controllers.BasePropertiesBean"/>
<jsp:useBean id="labelsBean" class="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Labels"/>

<c:if test="${SERVER_SETTINGS_GLOBAL == propertiesBean.properties[SERVER_SETTINGS]}">
    <c:set var="hideServerSettingsLocal" value="style='display:none'"/>
</c:if>

<c:if test="${AST_SETTINGS_UI == propertiesBean.properties[AST_SETTINGS]}">
    <c:set var="hideAstSettingsJson" value="style='display:none'"/>
</c:if>

<script type="text/javascript">
    $j(function () {
        $j("#ptaicss").load('${teamcityPluginResourcesPath.concat("css/ptai.css")}');
        window.console.log('PTAI CSS loaded');

        $j.getScript('${teamcityPluginResourcesPath.concat("js/ptai.js")}', function() {
            if (typeof BS.TestConnectionDialog === "undefined")
                $j.getScript("/js/bs/checkConnectionSettings.js");
            window.console.log('PTAI JS loaded');
            PtaiTaskSettingsForm.actionUrl('${TEST_CONTROLLER_PATH}');
            PtaiTaskSettingsForm.setupEventHandlers();
            window.console.log('${TEST_CONTROLLER_PATH}');

            $('${TOKEN}').getEncryptedPassword = function(pubKey) {
                let initialValueField = $("prop:encrypted:${TOKEN}");
                let initialValue = (initialValueField && initialValueField.value && initialValueField.value.length > 0) ? initialValueField.value : '';
                window.console.log('Initial value length ' + initialValue.length);
                if (0 === initialValue.length)
                    initialValue = BS.Encrypt.encryptData(this.value, pubKey);
                window.console.log('Sending initial value ' + initialValue);
                return initialValue;
            };
            window.console.log('getEncryptedPassword is set up');
        });
    });
</script>

<l:settingsGroup title="PT AI server connection settings">
    <tbody id="ptai-connection-settings" class="ptai-group">
    <tr>
        <th>
            <label for="${SERVER_SETTINGS}">${LABEL_SERVER_SETTINGS}</label></th>
        <td>
            <c:set var="onchange">
                let connectionSettingsLocal = $j('#ptai-connection-settings').find('.ptai-connection-settings-local');
                let comboBox = $('${SERVER_SETTINGS}');
                if ('${SERVER_SETTINGS_GLOBAL}' === comboBox[comboBox.selectedIndex].value)
                connectionSettingsLocal.hide();
                else
                connectionSettingsLocal.show();
                BS.MultilineProperties.updateVisible();
                BS.VisibilityHandlers.updateVisibility('mainContent');
            </c:set>
                <%-- Need to set enableFilter property as it makes combobox L&F like all others UI elements --%>
            <props:selectProperty
                    name="${SERVER_SETTINGS}" enableFilter="true"
                    className="mediumField" onchange="${onchange}">
                <props:option value="${SERVER_SETTINGS_GLOBAL}"
                              currValue="${propertiesBean.properties[SERVER_SETTINGS]}">${HINT_SERVER_SETTINGS_GLOBAL}</props:option>
                <props:option value="${SERVER_SETTINGS_LOCAL}"
                              currValue="${propertiesBean.properties[SERVER_SETTINGS]}">${HINT_SERVER_SETTINGS_LOCAL}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_SERVER_SETTINGS}</span>
            <span class="error" id="error_${SERVER_SETTINGS}"></span>
                <%-- Remaining properties are defined through model --%>
            <input type="hidden" id="global:${URL}" name="global:${URL}" value="<c:out value='${URL}'/>"/>
        </td>
    </tr>

    <tr class="ptai-connection-settings-local" ${hideServerSettingsLocal}>
        <th>
            <label for="${URL}">${LABEL_URL}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${URL}" className="longField"/>
            <span class="smallNote">${HINT_URL}</span>
            <span class="error" id="error_${URL}"></span>
        </td>
    </tr>

    <tr class="ptai-connection-settings-local" ${hideServerSettingsLocal}>
        <th>
            <label for="${TOKEN}">${LABEL_TOKEN}<l:star/></label>
        </th>
        <td>
                <%-- "props:..." values are defined through propertyBean--%>
            <props:passwordProperty name="${TOKEN}" className="longField"/>
            <span class="smallNote">${HINT_TOKEN}</span>
            <span class="error" id="error_${TOKEN}"></span>
        </td>
    </tr>

    <tr class="ptai-connection-settings-local" ${hideServerSettingsLocal}>
        <th>
            <label for="${CERTIFICATES}">${LABEL_CERTIFICATES}</label>
        </th>
        <td>
            <props:multilineProperty
                    name="${CERTIFICATES}"
                    className="longField"
                    linkTitle="Trust these CA certificates"
                    rows="3" cols="49" expanded="${true}"
                    note="${HINT_CERTIFICATES}"/>
            <span class="error" id="error_${CERTIFICATES}"></span>
        </td>
    </tr>

    <tr class="ptai-connection-settings-local" ${hideServerSettingsLocal}>
        <th>
            <label for="${INSECURE}">${LABEL_INSECURE}</label>
        </th>
        <td>
            <props:checkboxProperty name="${INSECURE}"/>
            <span class="smallNote">${HINT_INSECURE}</span>
            <span class="error" id="error_${INSECURE}"></span>
        </td>
    </tr>
    </tbody>
</l:settingsGroup>

<l:settingsGroup title="General AST settings">
    <tbody id="ptai-scan-settings" class="ptai-group">
    <tr>
        <th>
            <label for="${AST_SETTINGS}">${LABEL_AST_SETTINGS}</label></th>
        <td>
            <c:set var="onchange">
                let scanSettings = $j('#ptai-scan-settings');
                let scanSettingsUi = scanSettings.find('.ptai-scan-settings-ui');
                let scanSettingsJson = scanSettings.find('.ptai-scan-settings-json');

                let comboBox = $('${AST_SETTINGS}');
                if ('${AST_SETTINGS_UI}' === comboBox[comboBox.selectedIndex].value) {
                scanSettingsUi.show();
                scanSettingsJson.hide();
                } else {
                scanSettingsUi.hide();
                scanSettingsJson.show();
                }
                BS.MultilineProperties.updateVisible();
                BS.VisibilityHandlers.updateVisibility('mainContent');
            </c:set>
            <props:selectProperty
                    name="${AST_SETTINGS}" enableFilter="true"
                    className="mediumField" onchange="${onchange}">
                <props:option value="${AST_SETTINGS_UI}"
                              currValue="${propertiesBean.properties[AST_SETTINGS]}">${HINT_AST_SETTINGS_UI}</props:option>
                <props:option value="${AST_SETTINGS_JSON}"
                              currValue="${propertiesBean.properties[AST_SETTINGS]}">${HINT_AST_SETTINGS_JSON}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_AST_SETTINGS}</span>
            <span class="error" id="error_${AST_SETTINGS}"></span>
        </td>
    </tr>

    <tr class="ptai-scan-settings-ui">
        <th>
            <label for="${PROJECT_NAME}">${LABEL_PROJECT_NAME}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${PROJECT_NAME}" className="longField"/>
            <span class="smallNote">${HINT_PROJECT_NAME}</span>
                <%-- We do not implement custom error handler as teamcity does that for us:
                 it puts error message to error_${id} element (see submitBuildRunner
                 in editBuildType.js) --%>
            <span class="error" id="error_${PROJECT_NAME}"></span>
        </td>
    </tr>

    <tr class="ptai-scan-settings-json" ${hideAstSettingsJson}>
        <th>
            <label for="${JSON_SETTINGS}">${LABEL_JSON_SETTINGS}<l:star/></label>
        </th>
        <td>
            <props:multilineProperty
                    name="${JSON_SETTINGS}"
                    className="longField"
                    linkTitle="Edit JSON settings"
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_JSON_SETTINGS}"/>
            <span class="error" id="error_${JSON_SETTINGS}"></span>
        </td>
    </tr>

    <tr class="ptai-scan-settings-json" ${hideAstSettingsJson}>
        <th>
            <label for="${JSON_POLICY}">${LABEL_JSON_POLICY}</label>
        </th>
        <td>
            <props:multilineProperty
                    name="${JSON_POLICY}"
                    className="longField"
                    linkTitle="Edit JSON policy"
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_JSON_POLICY}"/>
            <span class="error" id="error_${JSON_POLICY}"></span>
        </td>
    </tr>

    <tr>
        <th>
            <label>${LABEL_STEP_FAIL_CONDITIONS}</label>
        </th>
        <td>
            <props:checkboxProperty name="${FAIL_IF_FAILED}"/>
            <label for="${FAIL_IF_FAILED}">${LABEL_FAIL_IF_FAILED}</label>
            <span class="smallNote">${HINT_FAIL_IF_FAILED}</span>
            <br>
            <props:checkboxProperty name="${FAIL_IF_UNSTABLE}"/>
            <label for="${FAIL_IF_UNSTABLE}">${LABEL_FAIL_IF_UNSTABLE}</label>
            <span class="smallNote">${HINT_FAIL_IF_UNSTABLE}</span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${VERBOSE}">${LABEL_VERBOSE}</label>
        </th>
        <td>
            <props:checkboxProperty name="${VERBOSE}"/>
            <span class="smallNote">${HINT_VERBOSE}</span>
        </td>
    </tr>
    </tbody>
</l:settingsGroup>

<l:settingsGroup title="Scan scope">
    <tbody class="ptai-group">
    <tr>
        <th>
            <label for="${INCLUDES}">${LABEL_INCLUDES}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${INCLUDES}" className="longField"/>
            <span class="smallNote">${HINT_INCLUDES}</span>
            <span class="error" id="error_${INCLUDES}"></span>
        </td>
    </tr>

    <tr>
        <th>
            <label for="${EXCLUDES}">${LABEL_EXCLUDES}</label>
        </th>
        <td>
            <props:textProperty name="${EXCLUDES}" className="longField"/>
            <span class="smallNote">${HINT_EXCLUDES}</span>
            <span class="error" id="error_${EXCLUDES}"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${REMOVE_PREFIX}">${LABEL_REMOVE_PREFIX}</label>
        </th>
        <td>
            <props:textProperty name="${REMOVE_PREFIX}" className="longField"/>
            <span class="smallNote">${HINT_REMOVE_PREFIX}</span>
            <span class="error" id="error_${REMOVE_PREFIX}"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${PATTERN_SEPARATOR}">${LABEL_PATTERN_SEPARATOR}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${PATTERN_SEPARATOR}" className="longField"/>
            <span class="smallNote">${HINT_PATTERN_SEPARATOR}</span>
            <span class="error" id="error_${PATTERN_SEPARATOR}"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${USE_DEFAULT_EXCLUDES}">${LABEL_USE_DEFAULT_EXCLUDES}</label>
        </th>
        <td>
            <props:checkboxProperty name="${USE_DEFAULT_EXCLUDES}"/>
            <span class="smallNote">${HINT_USE_DEFAULT_EXCLUDES}</span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${FLATTEN}">${LABEL_FLATTEN}</label>
        </th>
        <td>
            <props:checkboxProperty name="${FLATTEN}"/>
            <span class="smallNote">${HINT_FLATTEN}</span>
        </td>
    </tr>
    </tbody>
</l:settingsGroup>
<l:settingsGroup title="Check settings">
    <tbody class="ptai-group">
    <tr>
        <th>
        </th>
        <td>
            <div class="saveButtonsBlock">
                <c:set var="onclick">
                    PtaiTaskSettingsForm.test();
                </c:set>
                <forms:submit id="testSettings" type="button" label="<%=Labels.CHECK%>" onclick="${onclick}"/>
                <input type="hidden" id="mode" name="mode" value="modify"/>
                <forms:saving id="testingSettings"/>
                    <%-- testConnectionDialog, testConnectionStatus and testConnectionDetails are
                     identifiers that are hardcoded in testConnection.js --%>
                <bs:dialog dialogId="testConnectionDialog"
                           title="Test AST job job settings"
                           closeCommand="BS.TestConnectionDialog.close();"
                           closeAttrs="showdiscardchangesmessage='false'">
                    <div id="testConnectionStatus"></div>
                    <div id="testConnectionDetails" class="mono"></div>
                </bs:dialog>
            </div>
        </td>
    </tr>
    </tbody>
</l:settingsGroup>