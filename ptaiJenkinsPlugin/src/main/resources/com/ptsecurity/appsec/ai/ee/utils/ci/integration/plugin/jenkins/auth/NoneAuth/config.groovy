package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.auth.NoneAuth

import lib.FormTagLib

def f = namespace(FormTagLib)

f.block() {
    f.validateButton(
            title: _('testJenkinsServer'),
            progress: _('testJenkinsServerProgress'),
            method: "testJenkinsServer",
            with: 'jenkinsServerUrl,jenkinsJobName,serverCredentialsId'
    )
}