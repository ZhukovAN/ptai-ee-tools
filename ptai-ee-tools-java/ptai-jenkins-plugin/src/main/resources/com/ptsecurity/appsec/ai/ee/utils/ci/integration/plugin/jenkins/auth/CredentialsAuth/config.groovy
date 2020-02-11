package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.CredentialsAuth

import lib.CredentialsTagLib
import lib.FormTagLib

def f = namespace(FormTagLib)
def c = namespace(CredentialsTagLib)

f.entry(
        title: _('credentialsId'),
        field: 'credentialsId') {
    c.select()
}

f.block() {
    f.validateButton(
            title: _('testJenkinsServer'),
            progress: _('testJenkinsServerProgress'),
            method: "testJenkinsServer",
            with: 'jenkinsServerUrl,jenkinsJobName,serverLegacyCredentialsId,credentialsId'
    )
}