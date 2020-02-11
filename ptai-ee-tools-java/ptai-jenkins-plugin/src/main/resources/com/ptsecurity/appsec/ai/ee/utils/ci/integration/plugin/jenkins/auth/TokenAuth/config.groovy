package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.TokenAuth

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: _('userName'),
        field: 'userName') {
    f.textbox()
}

f.entry(
        title: _('apiToken'),
        field: 'apiToken') {
    f.password()
}

f.block() {
    f.validateButton(
            title: _('testJenkinsServer'),
            progress: _('testJenkinsServerProgress'),
            method: "testJenkinsServer",
            with: 'jenkinsServerUrl,jenkinsJobName,serverLegacyCredentialsId,userName,apiToken'
    )
}