package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ServerSettings

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

f.block() {
    f.validateButton(
            title: _('testServer'),
            progress: _('testServerProgress'),
            method: 'testServer',
            with: 'serverUrl,serverCredentialsId'
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
