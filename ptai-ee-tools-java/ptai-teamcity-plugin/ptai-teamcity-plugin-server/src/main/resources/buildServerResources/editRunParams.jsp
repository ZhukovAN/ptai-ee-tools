<%@ include file="common.jsp" %>
<%@ include file="constants.jsp" %>

<%-- During first adding new build step TeamCity loads plugin's RunType JSP form
 using BS.ajaxUpdater in admin/editRunType.jsp file. This AJAX request doesn't
 load JavaScripts Scripts included as <script src=... > in the body of the
 page (see https://teamcity-support.jetbrains.com/hc/en-us/community/posts/206690595-Javascript-not-loaded-the-first-time-a-new-build-runner-is-added).
 That means that we need to inline these scripts directly to JSP. And to avoid
 code duplication (as these scripts may be used somwhere else, i.e. in administrative
 page) we'll inject these scripts as JSP variables from model.--%>

<style id="ptaicss"></style>

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
--%>

<jsp:useBean id="propertiesBean" scope="request" type="jetbrains.buildServer.controllers.BasePropertiesBean"/>

<script type="text/javascript">
    $j(function() {
        $j("#ptaicss").load('${teamcityPluginResourcesPath.concat("css/ptai.css")}');

        $j.getScript('${teamcityPluginResourcesPath.concat("js/ptai.js")}', function() {
            if (typeof BS.TestConnectionDialog === "undefined")
                $j.getScript("/js/bs/testConnection.js");
            TaskConnectionSettingsForm.toggle(${propertiesBean.properties[SERVER_SETTINGS] == SERVER_SETTINGS_GLOBAL});
            TaskConnectionSettingsForm.setTestConnectionUrl('${ADMIN_CONTROLLER_PATH}');
            TaskConnectionSettingsForm.setupEventHandlers();
        });
    });
</script>
<%--
<script type="text/javascript">
    ${PTAIJS}
    $j(function() {
        alert(2020);
        TaskConnectionSettingsForm.toggle(${propertiesBean.properties[SERVER_SETTINGS] == SERVER_SETTINGS_GLOBAL});
        TaskConnectionSettingsForm.setTestConnectionUrl('${ADMIN_CONTROLLER_PATH}');
        TaskConnectionSettingsForm.setupEventHandlers();
        alert(2021);
    });
</script>
--%>

<%--
<script type="text/javascript">
    BaseEventHandler = OO.extend(BS.AbstractPasswordForm, {
        alertHandle: function() {
            alert("alertHandle");
        }
    });
    /*
    * Need to create form that can be bound to any element (native BS forms
    * use form.elements property that doesn't works with something else than
    * forms, i.e. div's). So I've overriden methods like enable / disable and
    * ported disableFormTemp / reenableForm from BS.Util.
    * In order to use this form on page, extend it and override formElement
    * and savingIndicator methods. Form on that page also need to provide
    * hidden "mode" field. This field may have following values:
    * - modify - something was changed on a form, no buttons were pressed.
    * Just to mark form as modified
    * - save - user clicked "save" button, so settings are to be checked and
    * saved to file
    * - test - user clicked "test" button, settings are to be checked and
    * connectivity test is to be performed*
    * */
    EventHandler = OO.extend(BaseEventHandler, {
        handle: function() {
            alert("handle");
        }
    });
</script>
--%>

<l:settingsGroup title="PT AI server connection settings">
    <tbody id="ai-connection-settings">
        <tr>
            <th>
                <label for="${SERVER_SETTINGS}">${LABEL_SERVER_SETTINGS}</label></th>
            <td>
                <c:set var="onchange">
                    let sel = $('${SERVER_SETTINGS}');
                    let settingsMode = sel[sel.selectedIndex].value;
                    TaskConnectionSettingsForm.toggle('${SERVER_SETTINGS_GLOBAL}' === settingsMode);
                </c:set>
                <%-- <c:set var="onchange">${JS3}</c:set> --%>
                <%-- Need to set enableFilter property as it makes combobox L&F like all others UI elements --%>
                <props:selectProperty
                        name="${SERVER_SETTINGS}" enableFilter="true"
                        className="mediumField" onchange="${onchange}">
                    <props:option value="${SERVER_SETTINGS_GLOBAL}" currValue="${propertiesBean.properties[SERVER_SETTINGS]}">${HINT_SERVER_SETTINGS_GLOBAL}</props:option>
                    <props:option value="${SERVER_SETTINGS_LOCAL}" currValue="${propertiesBean.properties[SERVER_SETTINGS]}">${HINT_SERVER_SETTINGS_LOCAL}</props:option>
                </props:selectProperty>
                <span class="smallNote">${HINT_SERVER_SETTINGS}</span>
               <%-- Remaining properties are defined through model --%>
                <input type="hidden" id="global:${URL}" name="global:${URL}" value="<c:out value='${URL}'/>"/>
                <input type="hidden" id="global:${USER}" name="global:${USER}" value="<c:out value='${USER}'/>"/>
            </td>
        </tr>

        <%--
        <tr>
            <th>
                <label for="${optionsBean.ptaiServerSettings}">${LABEL_SERVER_SETTINGS}</label>
            </th>
            <td>
                <c:set var="onclick">
                    BS.Util.hide('${LOCAL_URL}Container');
                    BS.Util.hide('${LOCAL_USER}Container');
                    BS.Util.hide('${LOCAL_TOKEN}Container');
                    BS.Util.hide('${optionsBean.ptaiServerLocalTrustedCertificates}Container');
                    BS.VisibilityHandlers.updateVisibility('mainContent');
                </c:set>
                <props:radioButtonProperty
                        name="${optionsBean.ptaiServerSettings}" id="${SERVER_SETTINGS_GLOBAL}"
                        value="${SERVER_SETTINGS_GLOBAL}"
                        checked="${SERVER_SETTINGS_GLOBAL == propertiesBean.properties[optionsBean.ptaiServerSettings]}"
                        onclick="${onclick}"/>
                <label for="${SERVER_SETTINGS_GLOBAL}">${LABEL_SERVER_SETTINGS_GLOBAL}</label>

                <span style="padding-left: 2em">
                    <c:set var="onclick">
                        BS.Util.show('${LOCAL_URL}Container');
                        BS.Util.show('${LOCAL_USER}Container');
                        BS.Util.show('${LOCAL_TOKEN}Container');
                        BS.Util.show('${optionsBean.ptaiServerLocalTrustedCertificates}Container');
                        BS.VisibilityHandlers.updateVisibility('mainContent');
                    </c:set>
                    <props:radioButtonProperty
                            name="${optionsBean.ptaiServerSettings}" id="${SERVER_SETTINGS_LOCAL}"
                            value="${SERVER_SETTINGS_LOCAL}"
                            checked="${SERVER_SETTINGS_LOCAL == propertiesBean.properties[optionsBean.ptaiServerSettings]}"
                            onclick="${onclick}"/>
                    <label for="${SERVER_SETTINGS_LOCAL}">${LABEL_SERVER_SETTINGS_LOCAL}</label>
                </span>
            </td>
        </tr>
        --%>

        <tr class="ai-connection-settings-local" style="display:none;">
            <th>
                <label for="${URL}">${LABEL_URL}<l:star/></label>
            </th>
            <td>
                <props:textProperty name="${URL}" className="longField"/>
                <span class="smallNote">${HINT_URL}</span>
                <span class="error" id="${URL}Error"></span>
            </td>
        </tr>
        <tr class="ai-connection-settings-local" style="display:none;">
            <th>
                <label for="${USER}">${LABEL_USER}<l:star/></label>
            </th>
            <td>
                <props:textProperty name="${USER}" className="longField"/>
                <span class="smallNote">${HINT_USER}</span>
                <span class="error" id="${USER}Error"></span>
            </td>
        </tr>

        <tr class="ai-connection-settings-local" style="display:none;">
            <th>
                <label for="${TOKEN}">${LABEL_TOKEN}<l:star/></label>
            </th>
            <td>
                <%-- "props:..." values are defined through propertyBean--%>
                <props:passwordProperty name="${TOKEN}" className="longField"/>
                <input type="hidden" id="mode" name="mode" value="modify"/>
                <span class="smallNote">${HINT_TOKEN}</span>
                <span class="error" id="${TOKEN}Error"></span>
            </td>
        </tr>

        <tr class="ai-connection-settings-local" style="display:none;">
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
                <span class="error" id="${CERTIFICATES}Error"></span>
            </td>
        </tr>
        <tr>
            <th colspan="2" class="noBorder">
                <div class="saveButtonsBlock">
                <forms:submit id="testConnection" type="button" label="<%=Labels.TEST%>" />
                <forms:saving id="testingConnection"/>
                </div>
                <%-- testConnectionDialog, testConnectionStatus and testConnectionDetails are
                 identifiers that are hardcoded in testConnection.js --%>
                <bs:dialog dialogId="testConnectionDialog"
                           title="Test PT AI server connection"
                           closeCommand="BS.TestConnectionDialog.close();"
                           closeAttrs="showdiscardchangesmessage='false'">
                    <div id="testConnectionStatus"></div>
                    <div id="testConnectionDetails" class="mono"></div>
                </bs:dialog>
            </th>
        </tr>
    </tbody>
</l:settingsGroup>

<l:settingsGroup className="ai-title" title="General AST settings">

    <c:if test="${propertiesBean.properties[AST_SETTINGS] == AST_SETTINGS_UI}">
        <c:set var="hideJson" value="style='display:none'"/>
    </c:if>

    <c:if test="${propertiesBean.properties[AST_SETTINGS] == AST_SETTINGS_JSON}">
        <c:set var="hideUi" value="style='display:none'"/>
    </c:if>

    <tr>
        <th>
            <label for="${AST_SETTINGS}">${LABEL_AST_SETTINGS}</label></th>
        <td>
            <c:set var="onchange">
                var sel = $('${AST_SETTINGS}');
                var settingsMode = sel[sel.selectedIndex].value;
                if ('${AST_SETTINGS_JSON}' == settingsMode) {
                    BS.Util.show('${JSON_SETTINGS}Container');
                    BS.Util.show('${JSON_POLICY}Container');
                    BS.Util.hide('${PROJECT_NAME}Container');
                } else if ('${AST_SETTINGS_UI}' == settingsMode) {
                    BS.Util.hide('${JSON_SETTINGS}Container');
                    BS.Util.hide('${JSON_POLICY}Container');
                    BS.Util.show('${PROJECT_NAME}Container');
                }
                BS.MultilineProperties.updateVisible();
                BS.VisibilityHandlers.updateVisibility('mainContent');
            </c:set>
            <props:selectProperty
                    name="${AST_SETTINGS}" enableFilter="true"
                    className="mediumField" onchange="${onchange}">
                <props:option value="${AST_SETTINGS_UI}" currValue="${propertiesBean.properties[AST_SETTINGS]}">${HINT_AST_SETTINGS_UI}</props:option>
                <props:option value="${AST_SETTINGS_JSON}" currValue="${propertiesBean.properties[AST_SETTINGS]}">${HINT_AST_SETTINGS_JSON}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_AST_SETTINGS}</span>
        </td>
    </tr>

    <tr id="${PROJECT_NAME}Container" ${hideUi}>
        <th>
            <label for="${PROJECT_NAME}">${LABEL_PROJECT_NAME}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${PROJECT_NAME}" className="longField"/>
            <span class="smallNote">${HINT_PROJECT_NAME}</span>
            <span class="error" id="${PROJECT_NAME}Error"></span>
        </td>
    </tr>

    <tr id="${JSON_SETTINGS}Container" ${hideJson}>
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
            <span class="error" id="${JSON_SETTINGS}Error"></span>
        </td>
    </tr>
    <tr id="${JSON_POLICY}Container" ${hideJson}>
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
            <span class="error" id="${JSON_POLICY}Error"></span>
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
            <label for="${NODE_NAME}">${LABEL_NODE_NAME}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${NODE_NAME}" className="longField"/>
            <span class="smallNote">${HINT_NODE_NAME}</span>
            <span class="error" id="${NODE_NAME}Error"></span>
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
</l:settingsGroup>
<l:settingsGroup title="Scan scope">
    <tr>
        <th>
            <label for="${INCLUDES}">${LABEL_INCLUDES}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${INCLUDES}" className="longField"/>
            <span class="smallNote">${HINT_INCLUDES}</span>
            <span class="error" id="${INCLUDES}Error"></span>
        </td>
    </tr>

    <tr>
        <th>
            <label for="${EXCLUDES}">${LABEL_EXCLUDES}</label>
        </th>
        <td>
            <props:textProperty name="${EXCLUDES}" className="longField"/>
            <span class="smallNote">${HINT_EXCLUDES}</span>
            <span class="error" id="${EXCLUDES}Error"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${REMOVE_PREFIX}">${LABEL_REMOVE_PREFIX}</label>
        </th>
        <td>
            <props:textProperty name="${REMOVE_PREFIX}" className="longField"/>
            <span class="smallNote">${HINT_REMOVE_PREFIX}</span>
            <span class="error" id="${REMOVE_PREFIX}Error"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${PATTERN_SEPARATOR}">${LABEL_PATTERN_SEPARATOR}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${PATTERN_SEPARATOR}" className="longField"/>
            <span class="smallNote">${HINT_PATTERN_SEPARATOR}</span>
            <span class="error" id="${PATTERN_SEPARATOR}Error"></span>
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
</l:settingsGroup>
