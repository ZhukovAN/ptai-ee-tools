package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings

import lib.CredentialsTagLib
import lib.FormTagLib

def f = namespace(FormTagLib)
def c = namespace(CredentialsTagLib)

f.entry(
        title: _('serverUrl'),
        field: 'serverUrl') {
    f.textbox()
}

f.entry(
        title: _('serverCredentialsId'),
        field: 'serverCredentialsId') {
    c.select()
}

f.entry(
        title: _('serverInsecure'),
        field: 'serverInsecure',
        default: 'false') {
    f.checkbox()
}

f.block() {
    f.validateButton(
            title: _('testServer'),
            progress: _('testServerProgress'),
            method: 'testServer',
            with: 'serverUrl,serverCredentialsId,serverInsecure'
    )
}
