package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.SlimServerSettings

import lib.CredentialsTagLib
import lib.FormTagLib

def f = namespace(FormTagLib)
def c = namespace(CredentialsTagLib)

f.entry(
        title: _('serverSlimUrl'),
        field: 'serverSlimUrl') {
    f.textbox()
}

f.entry(
        title: _('serverSlimCredentialsId'),
        field: 'serverSlimCredentialsId') {
    c.select()
}

f.block() {
    f.validateButton(
            title: _('testServer'),
            progress: _('testServerProgress'),
            method: 'testServer',
            with: 'serverSlimUrl,serverSlimCredentialsId'
    )
}
