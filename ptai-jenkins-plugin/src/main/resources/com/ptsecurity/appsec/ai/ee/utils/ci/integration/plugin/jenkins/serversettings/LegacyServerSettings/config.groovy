package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.serversettings.LegacyServerSettings

import lib.CredentialsTagLib
import lib.FormTagLib

def f = namespace(FormTagLib)
def c = namespace(CredentialsTagLib)

f.entry(
        title: _('serverLegacyUrl'),
        field: 'serverLegacyUrl') {
    f.textbox()
}

f.entry(
        title: _('serverLegacyCredentialsId'),
        field: 'serverLegacyCredentialsId') {
    c.select()
}

f.block() {
    f.validateButton(
            title: _('testServer'),
            progress: _('testServerProgress'),
            method: 'testServer',
            with: 'serverLegacyUrl,serverLegacyCredentialsId'
    )
}

f.entry(
        title: _('jenkinsServerUrl'),
        field: 'jenkinsServerUrl') {
    f.textbox()
}

f.entry(
        title: _('jenkinsJobName'),
        field: 'jenkinsJobName') {
    f.textbox()
}

f.dropdownDescriptorSelector(
        title: _('jenkinsServerCredentials'),
        field: 'jenkinsServerCredentials',
        descriptors: descriptor.getAuthDescriptors(),
        default: descriptor.getDefaultAuthDescriptor()
)

f.advanced() {
    f.entry(
            title: _('jenkinsMaxRetry'),
            field: 'jenkinsMaxRetry') {
        f.textbox(default: descriptor.serverSettingsDefaults.jenkinsMaxRetry)
    }
    f.entry(
            title: _('jenkinsRetryDelay'),
            field: 'jenkinsRetryDelay') {
        f.textbox(default: descriptor.serverSettingsDefaults.jenkinsRetryDelay)
    }
}


