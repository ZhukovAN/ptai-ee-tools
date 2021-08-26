package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.ServerSettings

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.CredentialsTagLib
import lib.FormTagLib

def f = namespace(FormTagLib)
def c = namespace(CredentialsTagLib)

f.entry(
        title: Resources.i18n_ast_settings_server_url_label(),
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
