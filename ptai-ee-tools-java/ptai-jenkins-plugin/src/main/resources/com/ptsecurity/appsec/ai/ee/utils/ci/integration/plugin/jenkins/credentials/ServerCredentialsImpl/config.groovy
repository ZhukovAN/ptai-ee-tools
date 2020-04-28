package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentialsImpl

import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.entry(
        title: _('clientCertificate'),
        field: 'clientCertificate') {
    f.textarea(
            style: 'height:100px',
            checkMethod: 'post')
}

f.entry(
        title: _('clientKey'),
        field: 'clientKey') {
    f.password()
}

f.block() {
    f.validateButton(
            title: _('testClientCertificate'),
            progress: _('testClientCertificateProgress'),
            method: 'testClientCertificate',
            with: 'clientCertificate,clientKey'
    )
}

f.entry(
        title: _('serverCaCertificates'),
        field: 'serverCaCertificates') {
    f.textarea(
            style: 'height:100px',
            checkMethod: 'post')
}

f.block() {
    f.validateButton(
            title: _('testServerCaCertificates'),
            progress: _('testServerCaCertificatesProgress'),
            method: 'testServerCaCertificates',
            with: 'serverCaCertificates'
    )
}

st.include(
    page: 'id-and-description',
    class: descriptor.clazz
)

