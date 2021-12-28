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

<script type="text/javascript">
    $j(function () {
        $j("#ptaicss").load('${teamcityPluginResourcesPath.concat("css/ptai.css")}');
        window.console.log('PTAI CSS loaded');

        $j.getScript('${teamcityPluginResourcesPath.concat("js/ptai.js")}', function() {
            if (typeof BS.TestConnectionDialog === "undefined")
                $j.getScript("/js/bs/checkConnectionSettings.js");
            window.console.log('PT AI JavaScript module loaded');
            PtaiTaskSettingsForm.actionUrl('${TEST_CONTROLLER_PATH}');
            PtaiTaskSettingsForm.setupEventHandlers();
            window.console.log('PT AI task settings form initialized');
        });

        $('${SERVER_SETTINGS_LOCAL_TOKEN}').getEncryptedPassword = function(pubKey) {
            let initialValueField = $("prop:encrypted:${SERVER_SETTINGS_LOCAL_TOKEN}");
            let initialValue = (initialValueField && initialValueField.value && initialValueField.value.length > 0) ? initialValueField.value : '';
            if (0 === initialValue.length)
                initialValue = BS.Encrypt.encryptData(this.value, pubKey);
            window.console.log('Sending encrypted password value ' + initialValue);
            return initialValue;
        };

        // Array of table row identifiers that are to be shown if local connection settings mode selected
        var ptaiServerSettingsLocalFieldRows = [
            'row_${SERVER_SETTINGS_LOCAL_URL}',
            'row_${SERVER_SETTINGS_LOCAL_TOKEN}',
            'row_${SERVER_SETTINGS_LOCAL_CERTIFICATES}',
            'row_${SERVER_SETTINGS_LOCAL_INSECURE}' ];

        // ... converts array to varargs
        ptaiServerSettingsChange = function () {
            let mode = $('${SERVER_SETTINGS}').value;
            if (mode === '${SERVER_SETTINGS_GLOBAL}')
                BS.Util.hide(...ptaiServerSettingsLocalFieldRows);
            if (mode === '${SERVER_SETTINGS_LOCAL}')
                BS.Util.show(...ptaiServerSettingsLocalFieldRows);
            BS.MultilineProperties.updateVisible();
        };

        // Array of table row identifiers that are to be shown if "UI" AST settings mode selected
        var ptaiAstSettingsUiFieldRows = [ 'row_${AST_SETTINGS_UI_PROJECT_NAME}' ];
        // Array of table row identifiers that are to be shown if "JSON" AST settings mode selected
        var ptaiAstSettingsJsonFieldRows = [ 'row_${AST_SETTINGS_JSON_SETTINGS}', 'row_${AST_SETTINGS_JSON_POLICY}' ];

        ptaiAstSettingsChange = function () {
            let mode = $('${AST_SETTINGS}').value;
            if (mode === '${AST_SETTINGS_UI}') {
                BS.Util.show(...ptaiAstSettingsUiFieldRows);
                BS.Util.hide(...ptaiAstSettingsJsonFieldRows);
            }
            if (mode === '${AST_SETTINGS_JSON}') {
                BS.Util.hide(...ptaiAstSettingsUiFieldRows);
                BS.Util.show(...ptaiAstSettingsJsonFieldRows);
            }
            BS.MultilineProperties.updateVisible();
        };

        // Array of table row identifiers that are to be shown if report generation option is checked
        var ptaiReportingReportFieldRows = [
            'row_${REPORTING_REPORT_FILE}',
            'row_${REPORTING_REPORT_TEMPLATE}',
            'row_${REPORTING_REPORT_FORMAT}',
            'row_${REPORTING_REPORT_LOCALE}',
            'row_${REPORTING_REPORT_FILTER}' ];

        ptaiReportingReportShowHide = function (show) {
            if (true == show)
                BS.Util.show(...ptaiReportingReportFieldRows);
            else
                BS.Util.hide(...ptaiReportingReportFieldRows);
            BS.MultilineProperties.updateVisible();
        };

        // Array of table row identifiers that are to be shown if data export option is checked
        var ptaiReportingDataFieldRows = [
            'row_${REPORTING_DATA_FILE}',
            'row_${REPORTING_DATA_FORMAT}',
            'row_${REPORTING_DATA_LOCALE}',
            'row_${REPORTING_DATA_FILTER}' ];

        ptaiReportingDataShowHide = function (show) {
            if (true == show)
                BS.Util.show(...ptaiReportingDataFieldRows);
            else
                BS.Util.hide(...ptaiReportingDataFieldRows);
            BS.MultilineProperties.updateVisible();
        };

        // Array of table row identifiers that are to be shown if raw data export option is checked
        var ptaiReportingRawDataFieldRows = [
            'row_${REPORTING_RAWDATA_FILE}',
            'row_${REPORTING_RAWDATA_FILTER}' ];

        ptaiReportingRawDataShowHide = function (show) {
            if (true == show)
                BS.Util.show(...ptaiReportingRawDataFieldRows);
            else
                BS.Util.hide(...ptaiReportingRawDataFieldRows);
            BS.MultilineProperties.updateVisible();
        };

        // Array of table row identifiers that are to be shown if SARIF report export option is checked
        var ptaiReportingSarifFieldRows = [
            'row_${REPORTING_SARIF_FILE}',
            'row_${REPORTING_SARIF_FILTER}' ];

        ptaiReportingSarifShowHide = function (show) {
            if (true == show)
                BS.Util.show(...ptaiReportingSarifFieldRows);
            else
                BS.Util.hide(...ptaiReportingSarifFieldRows);
            BS.MultilineProperties.updateVisible();
        };

        // Array of table row identifiers that are to be shown if SARIF report export option is checked
        var ptaiReportingSonarGiifFieldRows = [
            'row_${REPORTING_SONARGIIF_FILE}',
            'row_${REPORTING_SONARGIIF_FILTER}' ];

        ptaiReportingSonarGiifShowHide = function (show) {
            if (true == show)
                BS.Util.show(...ptaiReportingSonarGiifFieldRows);
            else
                BS.Util.hide(...ptaiReportingSonarGiifFieldRows);
            BS.MultilineProperties.updateVisible();
        };

        ptaiReportingJsonShowHide = function (show) {
            if (true == show)
                BS.Util.show('row_${REPORTING_JSON_SETTINGS}');
            else
                BS.Util.hide('row_${REPORTING_JSON_SETTINGS}');
            BS.MultilineProperties.updateVisible();
        };

        ptaiReportingReportClick = function () {
            ptaiReportingReportShowHide($('${REPORTING_REPORT}').checked)
        };

        ptaiReportingDataClick = function () {
            ptaiReportingDataShowHide($('${REPORTING_DATA}').checked)
        };

        ptaiReportingRawDataClick = function () {
            ptaiReportingRawDataShowHide($('${REPORTING_RAWDATA}').checked)
        };

        ptaiReportingSarifClick = function () {
            ptaiReportingSarifShowHide($('${REPORTING_SARIF}').checked)
        };

        ptaiReportingSonarGiifClick = function () {
            ptaiReportingSonarGiifShowHide($('${REPORTING_SONARGIIF}').checked)
        };

        ptaiReportingJsonClick = function () {
            ptaiReportingJsonShowHide($('${REPORTING_JSON}').checked)
        };

        // Array of table row identifiers that are to be shown if synchronous work mode is checked
        var ptaiAstWorkModeSyncFieldRows = [
            'row_ptaiStepFailConditions',
            'row_${REPORTING_REPORT}',
            'row_${REPORTING_DATA}',
            'row_${REPORTING_RAWDATA}',
            'row_${REPORTING_SARIF}',
            'row_${REPORTING_SONARGIIF}',
            'row_${REPORTING_JSON}' ];

        ptaiAstWorkModeChange = function () {
            let mode = $('${AST_MODE}').value;
            if (mode === '${AST_MODE_ASYNC}') {
                BS.Util.hide(...ptaiAstWorkModeSyncFieldRows);
                ptaiReportingReportShowHide(false);
                ptaiReportingDataShowHide(false);
                ptaiReportingRawDataShowHide(false);
                ptaiReportingSarifShowHide(false);
                ptaiReportingSonarGiifShowHide(false);
                ptaiReportingJsonShowHide(false);
            }
            if (mode === '${AST_MODE_SYNC}') {
                BS.Util.show(...ptaiAstWorkModeSyncFieldRows);
                ptaiReportingReportClick();
                ptaiReportingDataClick();
                ptaiReportingRawDataClick();
                ptaiReportingSarifClick();
                ptaiReportingSonarGiifClick();
                ptaiReportingJsonClick();
            }
            BS.MultilineProperties.updateVisible();
        };

        ptaiServerSettingsChange();
        ptaiAstSettingsChange();
        ptaiAstWorkModeChange();
    });
</script>

<l:settingsGroup title="PT AI server connection settings">
    <tbody id="ptai-connection-settings" class="ptai-group">
    <tr id="row_${SERVER_SETTINGS}">
        <th>
            <label for="${SERVER_SETTINGS}">${LABEL_SERVER_SETTINGS}</label></th>
        <td>
                <%-- Need to set enableFilter property as it makes combobox L&F like all others UI elements --%>
            <props:selectProperty
                    name="${SERVER_SETTINGS}" enableFilter="true"
                    className="mediumField" onchange="ptaiServerSettingsChange()">
                <props:option value="${SERVER_SETTINGS_GLOBAL}"
                              currValue="${propertiesBean.properties[SERVER_SETTINGS]}">${HINT_SERVER_SETTINGS_GLOBAL}</props:option>
                <props:option value="${SERVER_SETTINGS_LOCAL}"
                              currValue="${propertiesBean.properties[SERVER_SETTINGS]}">${HINT_SERVER_SETTINGS_LOCAL}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_SERVER_SETTINGS}</span>
            <span class="error" id="error_${SERVER_SETTINGS}"></span>
        </td>
    </tr>

    <tr id="row_${SERVER_SETTINGS_LOCAL_URL}">
        <th>
            <label for="${SERVER_SETTINGS_LOCAL_URL}">${LABEL_SERVER_SETTINGS_LOCAL_URL}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${SERVER_SETTINGS_LOCAL_URL}" className="longField"/>
            <span class="smallNote">${HINT_SERVER_SETTINGS_LOCAL_URL}</span>
            <span class="error" id="error_${SERVER_SETTINGS_LOCAL_URL}"></span>
        </td>
    </tr>

    <tr id="row_${SERVER_SETTINGS_LOCAL_TOKEN}">
        <th>
            <label for="${SERVER_SETTINGS_LOCAL_TOKEN}">${LABEL_SERVER_SETTINGS_LOCAL_TOKEN}<l:star/></label>
        </th>
        <td>
                <%-- "props:..." values are defined through propertyBean--%>
            <props:passwordProperty name="${SERVER_SETTINGS_LOCAL_TOKEN}" className="longField"/>
            <span class="smallNote">${HINT_SERVER_SETTINGS_LOCAL_TOKEN}</span>
            <span class="error" id="error_${SERVER_SETTINGS_LOCAL_TOKEN}"></span>
        </td>
    </tr>

    <tr id="row_${SERVER_SETTINGS_LOCAL_CERTIFICATES}">
        <th>
            <label for="${SERVER_SETTINGS_LOCAL_CERTIFICATES}">${LABEL_SERVER_SETTINGS_LOCAL_CERTIFICATES}</label>
        </th>
        <td>
            <props:multilineProperty
                    name="${SERVER_SETTINGS_LOCAL_CERTIFICATES}"
                    className="longField"
                    linkTitle="Trust these CA certificates"
                    rows="3" cols="49" expanded="${true}"
                    note="${HINT_SERVER_SETTINGS_LOCAL_CERTIFICATES}"/>
            <span class="error" id="error_${SERVER_SETTINGS_LOCAL_CERTIFICATES}"></span>
        </td>
    </tr>

    <tr id="row_${SERVER_SETTINGS_LOCAL_INSECURE}">
        <th>
            <label for="${SERVER_SETTINGS_LOCAL_INSECURE}">${LABEL_SERVER_SETTINGS_LOCAL_INSECURE}</label>
        </th>
        <td>
            <props:checkboxProperty name="${SERVER_SETTINGS_LOCAL_INSECURE}"/>
            <span class="smallNote">${HINT_SERVER_SETTINGS_LOCAL_INSECURE}</span>
            <span class="error" id="error_${SERVER_SETTINGS_LOCAL_INSECURE}"></span>
        </td>
    </tr>
    </tbody>
</l:settingsGroup>

<l:settingsGroup title="General AST settings">
    <tbody class="ptai-group">
    <tr id="row_${AST_SETTINGS}">
        <th>
            <label for="${AST_SETTINGS}">${LABEL_AST_SETTINGS}</label></th>
        <td>
            <props:selectProperty
                    name="${AST_SETTINGS}" enableFilter="true"
                    className="mediumField" onchange="ptaiAstSettingsChange()">
                <props:option value="${AST_SETTINGS_UI}"
                              currValue="${propertiesBean.properties[AST_SETTINGS]}">${HINT_AST_SETTINGS_UI}</props:option>
                <props:option value="${AST_SETTINGS_JSON}"
                              currValue="${propertiesBean.properties[AST_SETTINGS]}">${HINT_AST_SETTINGS_JSON}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_AST_SETTINGS}</span>
            <span class="error" id="error_${AST_SETTINGS}"></span>
        </td>
    </tr>

    <tr id="row_${AST_SETTINGS_UI_PROJECT_NAME}">
        <th>
            <label for="${AST_SETTINGS_UI_PROJECT_NAME}">${LABEL_AST_SETTINGS_UI_PROJECT_NAME}<l:star/></label>
        </th>
        <td>
            <props:textProperty name="${AST_SETTINGS_UI_PROJECT_NAME}" className="longField"/>
            <span class="smallNote">${HINT_AST_SETTINGS_UI_PROJECT_NAME}</span>
                <%-- We do not implement custom error handler as teamcity does that for us:
                 it puts error message to error_${id} element (see submitBuildRunner
                 in editBuildType.js) --%>
            <span class="error" id="error_${AST_SETTINGS_UI_PROJECT_NAME}"></span>
        </td>
    </tr>

    <tr  id="row_${AST_SETTINGS_JSON_SETTINGS}">
        <th>
            <label for="${AST_SETTINGS_JSON_SETTINGS}">${LABEL_AST_SETTINGS_JSON_SETTINGS}<l:star/></label>
        </th>
        <td>
            <props:multilineProperty
                    name="${AST_SETTINGS_JSON_SETTINGS}"
                    className="longField"
                    linkTitle="Edit JSON settings"
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_AST_SETTINGS_JSON_SETTINGS}"/>
            <span class="error" id="error_${AST_SETTINGS_JSON_SETTINGS}"></span>
        </td>
    </tr>

    <tr id="row_${AST_SETTINGS_JSON_POLICY}">
        <th>
            <label for="${AST_SETTINGS_JSON_POLICY}">${LABEL_AST_SETTINGS_JSON_POLICY}</label>
        </th>
        <td>
            <props:multilineProperty
                    name="${AST_SETTINGS_JSON_POLICY}"
                    className="longField"
                    linkTitle=""
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_AST_SETTINGS_JSON_POLICY}"/>
            <span class="error" id="error_${AST_SETTINGS_JSON_POLICY}"></span>
        </td>
    </tr>

    </tbody>
</l:settingsGroup>

<l:settingsGroup title="AST work mode">
    <tbody class="ptai-group">
    <tr id="row_${AST_MODE}">
        <th>
            <label for="${AST_MODE}">${LABEL_AST_MODE}</label></th>
        <td>
                <%-- Need to set enableFilter property as it makes combobox L&F like all others UI elements --%>
            <props:selectProperty
                    name="${AST_MODE}" enableFilter="true"
                    className="mediumField" onchange="ptaiAstWorkModeChange()">
                <props:option value="${AST_MODE_SYNC}"
                              currValue="${propertiesBean.properties[AST_MODE]}">${LABEL_AST_MODE_SYNC}</props:option>
                <props:option value="${AST_MODE_ASYNC}"
                              currValue="${propertiesBean.properties[AST_MODE]}">${LABEL_AST_MODE_ASYNC}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_AST_MODE}</span>
            <span class="error" id="error_${AST_MODE}"></span>
        </td>
    </tr>

    <tr id="row_ptaiStepFailConditions">
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

    <tr id="row_${REPORTING_REPORT}">
        <th>
            <label for="${REPORTING_REPORT}">${LABEL_REPORTING_REPORT}</label>
        </th>
        <td>
            <props:checkboxProperty name="${REPORTING_REPORT}" onclick="ptaiReportingReportClick()"/>
            <span class="smallNote">${HINT_REPORTING_REPORT}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_REPORT_FILE}">
        <th class="noBorder dense">
            <label for="${REPORTING_REPORT_FILE}">${LABEL_REPORTING_REPORT_FILE}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:textProperty name="${REPORTING_REPORT_FILE}" className="longField"/>
            <span class="smallNote">${HINT_REPORTING_REPORT_FILE}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_REPORT_TEMPLATE}">
        <th class="noBorder dense">
            <label for="${REPORTING_REPORT_TEMPLATE}">${LABEL_REPORTING_REPORT_TEMPLATE}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:textProperty name="${REPORTING_REPORT_TEMPLATE}" className="longField"/>
            <span class="smallNote">${HINT_REPORTING_REPORT_TEMPLATE}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_REPORT_FORMAT}">
        <th class="noBorder dense">
            <label for="${REPORTING_REPORT_FORMAT}">${LABEL_REPORTING_REPORT_FORMAT}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:selectProperty
                    name="${REPORTING_REPORT_FORMAT}" enableFilter="true" className="mediumField">
                <props:option value="${REPORTING_REPORT_FORMAT_HTML}"
                              currValue="${propertiesBean.properties[REPORTING_REPORT_FORMAT]}">${LABEL_REPORTING_REPORT_FORMAT_HTML}</props:option>
                <props:option value="${REPORTING_REPORT_FORMAT_PDF}"
                              currValue="${propertiesBean.properties[REPORTING_REPORT_FORMAT]}">${LABEL_REPORTING_REPORT_FORMAT_PDF}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_REPORTING_REPORT_FORMAT}</span>
            <span class="error" id="error_${REPORTING_REPORT_FORMAT}"></span>
        </td>
    </tr>
    <tr id="row_${REPORTING_REPORT_LOCALE}">
        <th class="noBorder dense">
            <label for="${REPORTING_REPORT_LOCALE}">${LABEL_REPORTING_REPORT_LOCALE}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:selectProperty
                    name="${REPORTING_REPORT_LOCALE}" enableFilter="true" className="mediumField">
                <props:option value="${REPORTING_LOCALE_ENGLISH}"
                              currValue="${propertiesBean.properties[REPORTING_REPORT_LOCALE]}">${LABEL_REPORTING_LOCALE_ENGLISH}</props:option>
                <props:option value="${REPORTING_LOCALE_RUSSIAN}"
                              currValue="${propertiesBean.properties[REPORTING_REPORT_LOCALE]}">${LABEL_REPORTING_LOCALE_RUSSIAN}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_REPORTING_REPORT_LOCALE}</span>
            <span class="error" id="error_${REPORTING_REPORT_LOCALE}"></span>
        </td>
    </tr>
    <tr id="row_${REPORTING_REPORT_FILTER}">
        <th class="noBorder dense">
            <label for="${REPORTING_REPORT_FILTER}">${LABEL_REPORTING_REPORT_FILTER}</label>
        </th>
        <td class="noBorder dense">
            <props:multilineProperty
                    name="${REPORTING_REPORT_FILTER}"
                    className="longField"
                    linkTitle=""
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_REPORTING_REPORT_FILTER}"/>
            <span class="error" id="error_${REPORTING_REPORT_FILTER}"></span>
        </td>
    </tr>

    <tr id="row_${REPORTING_DATA}">
        <th class="noBorder dense">
            <label for="${REPORTING_DATA}">${LABEL_REPORTING_DATA}</label>
        </th>
        <td>
            <props:checkboxProperty name="${REPORTING_DATA}" onclick="ptaiReportingDataClick()"/>
            <span class="smallNote">${HINT_REPORTING_DATA}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_DATA_FILE}">
        <th class="noBorder dense">
            <label for="${REPORTING_DATA_FILE}">${LABEL_REPORTING_DATA_FILE}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:textProperty name="${REPORTING_DATA_FILE}" className="longField"/>
            <span class="smallNote">${HINT_REPORTING_DATA_FILE}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_DATA_FORMAT}">
        <th class="noBorder dense">
            <label for="${REPORTING_DATA_FORMAT}">${LABEL_REPORTING_DATA_FORMAT}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:selectProperty
                    name="${REPORTING_DATA_FORMAT}" enableFilter="true" className="mediumField">
                <props:option value="${REPORTING_DATA_FORMAT_JSON}"
                              currValue="${propertiesBean.properties[REPORTING_DATA_FORMAT]}">${LABEL_REPORTING_DATA_FORMAT_JSON}</props:option>
                <props:option value="${REPORTING_DATA_FORMAT_XML}"
                              currValue="${propertiesBean.properties[REPORTING_DATA_FORMAT]}">${LABEL_REPORTING_DATA_FORMAT_XML}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_REPORTING_DATA_FORMAT}</span>
            <span class="error" id="error_${REPORTING_DATA_FORMAT}"></span>
        </td>
    </tr>
    <tr id="row_${REPORTING_DATA_LOCALE}">
        <th class="noBorder dense">
            <label for="${REPORTING_DATA_LOCALE}">${LABEL_REPORTING_DATA_LOCALE}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:selectProperty
                    name="${REPORTING_DATA_LOCALE}" enableFilter="true" className="mediumField">
                <props:option value="${REPORTING_LOCALE_ENGLISH}"
                              currValue="${propertiesBean.properties[REPORTING_DATA_LOCALE]}">${LABEL_REPORTING_LOCALE_ENGLISH}</props:option>
                <props:option value="${REPORTING_LOCALE_RUSSIAN}"
                              currValue="${propertiesBean.properties[REPORTING_DATA_LOCALE]}">${LABEL_REPORTING_LOCALE_RUSSIAN}</props:option>
            </props:selectProperty>
            <span class="smallNote">${HINT_REPORTING_DATA_LOCALE}</span>
            <span class="error" id="error_${REPORTING_DATA_LOCALE}"></span>
        </td>
    </tr>
    <tr id="row_${REPORTING_DATA_FILTER}">
        <th class="noBorder dense">
            <label for="${REPORTING_DATA_FILTER}">${LABEL_REPORTING_DATA_FILTER}</label>
        </th>
        <td class="noBorder dense">
            <props:multilineProperty
                    name="${REPORTING_DATA_FILTER}"
                    className="longField"
                    linkTitle=""
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_REPORTING_DATA_FILTER}"/>
            <span class="error" id="error_${REPORTING_DATA_FILTER}"></span>
        </td>
    </tr>

    <tr id="row_${REPORTING_RAWDATA}">
        <th class="noBorder dense">
            <label for="${REPORTING_RAWDATA}">${LABEL_REPORTING_RAWDATA}</label>
        </th>
        <td>
            <props:checkboxProperty name="${REPORTING_RAWDATA}" onclick="ptaiReportingRawDataClick()"/>
            <span class="smallNote">${HINT_REPORTING_RAWDATA}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_RAWDATA_FILE}">
        <th class="noBorder dense">
            <label for="${REPORTING_RAWDATA_FILE}">${LABEL_REPORTING_RAWDATA_FILE}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:textProperty name="${REPORTING_RAWDATA_FILE}" className="longField"/>
            <span class="smallNote">${HINT_REPORTING_RAWDATA_FILE}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_RAWDATA_FILTER}">
        <th class="noBorder dense">
            <label for="${REPORTING_RAWDATA_FILTER}">${LABEL_REPORTING_RAWDATA_FILTER}</label>
        </th>
        <td class="noBorder dense">
            <props:multilineProperty
                    name="${REPORTING_RAWDATA_FILTER}"
                    className="longField"
                    linkTitle=""
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_REPORTING_RAWDATA_FILTER}"/>
            <span class="error" id="error_${REPORTING_RAWDATA_FILTER}"></span>
        </td>
    </tr>

    <tr id="row_${REPORTING_SARIF}">
        <th class="noBorder dense">
            <label for="${REPORTING_SARIF}">${LABEL_REPORTING_SARIF}</label>
        </th>
        <td>
            <props:checkboxProperty name="${REPORTING_SARIF}" onclick="ptaiReportingSarifClick()"/>
            <span class="smallNote">${HINT_REPORTING_SARIF}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_SARIF_FILE}">
        <th class="noBorder dense">
            <label for="${REPORTING_SARIF_FILE}">${LABEL_REPORTING_SARIF_FILE}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:textProperty name="${REPORTING_SARIF_FILE}" className="longField"/>
            <span class="smallNote">${HINT_REPORTING_SARIF_FILE}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_SARIF_FILTER}">
        <th class="noBorder dense">
            <label for="${REPORTING_SARIF_FILTER}">${LABEL_REPORTING_SARIF_FILTER}</label>
        </th>
        <td class="noBorder dense">
            <props:multilineProperty
                    name="${REPORTING_SARIF_FILTER}"
                    className="longField"
                    linkTitle=""
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_REPORTING_SARIF_FILTER}"/>
            <span class="error" id="error_${REPORTING_SARIF_FILTER}"></span>
        </td>
    </tr>


    <tr id="row_${REPORTING_SONARGIIF}">
        <th class="noBorder dense">
            <label for="${REPORTING_SONARGIIF}">${LABEL_REPORTING_SONARGIIF}</label>
        </th>
        <td>
            <props:checkboxProperty name="${REPORTING_SONARGIIF}" onclick="ptaiReportingSonarGiifClick()"/>
            <span class="smallNote">${HINT_REPORTING_SONARGIIF}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_SONARGIIF_FILE}">
        <th class="noBorder dense">
            <label for="${REPORTING_SONARGIIF_FILE}">${LABEL_REPORTING_SONARGIIF_FILE}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:textProperty name="${REPORTING_SONARGIIF_FILE}" className="longField"/>
            <span class="smallNote">${HINT_REPORTING_SONARGIIF_FILE}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_SONARGIIF_FILTER}">
        <th class="noBorder dense">
            <label for="${REPORTING_SONARGIIF_FILTER}">${LABEL_REPORTING_SONARGIIF_FILTER}</label>
        </th>
        <td class="noBorder dense">
            <props:multilineProperty
                    name="${REPORTING_SONARGIIF_FILTER}"
                    className="longField"
                    linkTitle=""
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_REPORTING_SONARGIIF_FILTER}"/>
            <span class="error" id="error_${REPORTING_SONARGIIF_FILTER}"></span>
        </td>
    </tr>

    <tr id="row_${REPORTING_JSON}">
        <th class="noBorder dense">
            <label for="${REPORTING_JSON}">${LABEL_REPORTING_JSON}</label>
        </th>
        <td>
            <props:checkboxProperty name="${REPORTING_JSON}" onclick="ptaiReportingJsonClick()"/>
            <span class="smallNote">${HINT_REPORTING_JSON}</span>
        </td>
    </tr>
    <tr id="row_${REPORTING_JSON_SETTINGS}">
        <th class="noBorder dense">
            <label for="${REPORTING_JSON_SETTINGS}">${LABEL_REPORTING_JSON_SETTINGS}<l:star/></label>
        </th>
        <td class="noBorder dense">
            <props:multilineProperty
                    name="${REPORTING_JSON_SETTINGS}"
                    className="longField"
                    linkTitle=""
                    rows="3"
                    cols="49"
                    expanded="${true}"
                    note="${HINT_REPORTING_JSON_SETTINGS}"/>
            <span class="error" id="error_${REPORTING_JSON_SETTINGS}"></span>
        </td>
    </tr>

    <tr class="advancedSetting">
        <th>
            <label for="${FULL_SCAN_MODE}">${LABEL_FULL_SCAN_MODE}</label>
        </th>
        <td>
            <props:checkboxProperty name="${FULL_SCAN_MODE}"/>
            <span class="smallNote">${HINT_FULL_SCAN_MODE}</span>
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

