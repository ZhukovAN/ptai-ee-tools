<%@include file="/include.jsp" %>
<div>
    <form id="ptaiAdminForm" action="<c:url value='/ptai/adminSettings.html'/>" method="post">

      <table class="runnerFormTable">
        <tr class="groupingTitle">
          <td colspan="2">PTAI Server</td>
        </tr>

        <tr>
          <th><label for="ptaiServerUrl">PTAI server URL<l:star/></label></th>
          <td>
            <forms:textField name="ptaiServerUrl" value="${ptaiServerUrl}" className="longField"/>
            <span class="error" id="invalid_ptaiServerUrl"></span>
          </td>
        </tr>

        <tr>
          <th><label for="caCertsPem">Jenkins and PT AI server CA certificates
            <bs:helpIcon iconTitle="Comma separated list of include or exclude wildcard patterns. Exclude patterns start with exclamation mark \"!\". Example: **/*.java, **/*.html, !**/test/**/XYZ*"/></label></th>
          <td><textarea rows="5" cols="50" name="caCertsPem" wrap="off">${caCertsPem}</textarea>
          </td>
        </tr>

        <tr>
          <th><label for="ptaiKeyPem">PT AI client certificate
            <bs:helpIcon iconTitle="Comma separated list of include or exclude wildcard patterns. Exclude patterns start with exclamation mark \"!\". Example: **/*.java, **/*.html, !**/test/**/XYZ*"/></label></th>
          <td><textarea rows="5" cols="50" name="ptaiKeyPem" wrap="off">${ptaiKeyPem}</textarea>
          </td>
        </tr>

        <tr>
          <th><label for="ptaiKeyPemPassword">PT AI client certificate password<l:star/></label></th>
          <td>
            <input type="password" id="ptaiKeyPemPassword" name="ptaiKeyPemPassword" value="${ptaiKeyPemPassword}" class="longField"/>
            <span class="error" id="invalid_ptaiKeyPemPassword"></span>
          </td>
        </tr>

        <tr>
          <th><label for="jenkinsServerUrl">Jenkins server URL<l:star/></label></th>
          <td>
            <forms:textField name="jenkinsServerUrl" value="${jenkinsServerUrl}" className="longField"/>
            <span class="error" id="invalid_jenkinsServerUrl"></span>
          </td>
        </tr>

        <tr>
          <th><label for="jenkinsJobName">Main SAST job name<l:star/></label></th>
          <td>
            <forms:textField name="jenkinsJobName" value="${jenkinsJobName}" className="longField"/>
            <span class="error" id="invalid_jenkinsJobName"></span>
          </td>
        </tr>

        <tr>
          <th><label for="jenkinsLogin">User name<l:star/></label></th>
          <td>
            <forms:textField name="jenkinsLogin" value="${jenkinsLogin}" className="longField"/>
            <span class="error" id="invalid_jenkinsLogin"></span>
          </td>
        </tr>

        <tr>
          <th><label for="jenkinsPassword">Password<l:star/></label></th>
          <td>
            <input type="password" id="jenkinsPassword" name="jenkinsPassword" value="${jenkinsPassword}" class="longField"/>
            <span class="error" id="invalid_jenkinsPassword"></span>
          </td>
        </tr>
      </table>

      <div class="saveButtonsBlock">
        <input class="submitButton" type="submit" value="Save">
        <forms:saving/>
      </div>
    </form>
</div>