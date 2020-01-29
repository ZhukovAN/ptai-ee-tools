<%@include file="/include.jsp" %>

<bs:linkCSS dynamic="${true}">
   /css/admin/adminMain.css
   /css/admin/serverConfig.css
</bs:linkCSS>

<bs:linkScript>
    /js/bs/testConnection.js
    ${teamcityPluginResourcesPath}js/ptaiSettings.js
</bs:linkScript>

<script type="text/javascript">
    $j(function() {
        PtaiAdmin.SettingsForm.setupEventHandlers();
    });
</script>

<%-- <jsp:useBean id="propertiesBean" scope="request" type="jetbrains.buildServer.controllers.BasePropertiesBean"/> --%>
<jsp:useBean id="ptaiAdminSettings"
             scope="request"
             type="com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.PtaiAdminSettingsBean"/>

<div id="settingsContainer">
    <form id="ptaiAdminForm" action="<c:url value='/ptai/adminSettings.html'/>" method="post" onsubmit="return PtaiAdmin.SettingsForm.submitSettings()">

      <table class="runnerFormTable">
        <tr class="groupingTitle">
          <td colspan="2">PTAI Server</td>
        </tr>

        <tr>
          <th><label for="ptaiServerUrl">PTAI server URL<l:star/></label></th>
          <td>
            <forms:textField name="ptaiServerUrl" value="${ptaiAdminSettings.ptaiServerUrl}" className="longField"/>
            <span class="smallNote">PTAI application server REST API address and port. By default, PTAI application server REST API is using secure port 443. For Example: https://ptai.domain.org:443</span>
            <span class="error" id="ptaiServerUrlError"></span>
          </td>
        </tr>
        <tr>
          <th><label for="caCertsPem">Jenkins and PT AI server CA certificates</label></th>
          <td>
            <textarea name="caCertsPem" id="caCertsPem" rows="5" cols="50" wrap="off" className="longField"/>${ptaiAdminSettings.caCertsPem}</textarea>
            <span class="smallNote">CloudShell Sandbox API address and port. By default, the Sandbox API is using port 82.
                                    For Example: http://192.168.1.1:82 or https://10.10.19.1:82</span>
            <span class="error" id="caCertsPemError"></span>
          </td>
        </tr>
        <tr>
          <th><label for="ptaiKeyPem">PT AI client certificate
            <td><textarea rows="5" cols="50" name="ptaiKeyPem" wrap="off">${ptaiAdminSettings.ptaiKeyPem}</textarea>
            <span class="smallNote">The string is a PEM representation of PFX file with a certificate and private key. May be generated out of PFX file with openssl pkcs12 -in client.pfx -out client.pem -passin pass:P@ssw0rd -passout pass:P@ssw0rd</span>
            <span class="error" id="ptaiKeyPemError"></span>
          </td>
        </tr>

        <tr>
          <th><label for="ptaiKeyPemPassword">PT AI client certificate password</label></th>
          <td>
            <input type="password" id="ptaiKeyPemPassword" name="ptaiKeyPemPassword" value="${ptaiAdminSettings.ptaiKeyPemPassword}" class="longField"/>
            <span class="smallNote">Password for PT AI client key container</span>
            <span class="error" id="invalid_ptaiKeyPemPassword"></span>
          </td>
        </tr>

        <tr>
          <th><label for="jenkinsServerUrl">Jenkins server URL<l:star/></label></th>
          <td>
            <forms:textField name="jenkinsServerUrl" value="${ptaiAdminSettings.jenkinsServerUrl}" className="longField"/>
            <span class="error" id="jenkinsServerUrlError"></span>
          </td>
        </tr>

        <tr>
          <th><label for="jenkinsJobName">Main SAST job name<l:star/></label></th>
          <td>
            <forms:textField name="jenkinsJobName" value="${ptaiAdminSettings.jenkinsJobName}" className="longField"/>
            <span class="fieldExplanation">CloudShell password of the given user, In order to authenticate through the Sandbox API.</span>
            <span class="error" id="jenkinsJobNameError"></span>
          </td>
        </tr>

        <tr>
          <th><label for="jenkinsLogin">User name<l:star/></label></th>
          <td>
            <forms:textField name="jenkinsLogin" value="${ptaiAdminSettings.jenkinsLogin}" className="longField"/>
            <span class="smallNote">The CloudShell user name to use. This user will be used to authenticate through the Sandbox API.</span>
            <span class="error" id="jenkinsLoginError"></span>
          </td>
        </tr>

        <tr>
          <th><label for="jenkinsPassword">Password<l:star/></label></th>
          <td>
            <input type="password" id="jenkinsPassword" name="jenkinsPassword" value="${ptaiAdminSettings.jenkinsPassword}" class="longField"/>
          </td>
        </tr>
      </table>

      <div class="saveButtonsBlock">
        <forms:submit type="submit" label="Save" />
        <forms:submit id="testConnection" type="button" label="Test Connection"/>
        <input type="hidden" id="submitSettings" name="submitSettings" value="store"/>
        <input type="hidden" id="publicKey" name="publicKey"
               value="<c:out value='${ptaiAdminSettings.hexEncodedPublicKey}'/>"/>
        <forms:saving/>
      </div>
    </form>
    <bs:dialog dialogId="testConnectionDialog"
               title="Test Connection"
               closeCommand="BS.TestConnectionDialog.close();"
               closeAttrs="showdiscardchangesmessage='false'">
        <div id="testConnectionStatus"></div>
        <div id="testConnectionDetails" class="mono"></div>
    </bs:dialog>
    <forms:modified/>
</div>

