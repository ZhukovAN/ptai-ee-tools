package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.ServerCredentialsImpl

def f = namespace(lib.FormTagLib);
def c = namespace(lib.CredentialsTagLib)
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
            progress: _('clientCertificateChecking'),
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
            progress: _('serverCaCertificatesChecking'),
            method: 'testServerCaCertificates',
            with: 'serverCaCertificates'
    )
}

st.include(
    page: 'id-and-description',
    class: descriptor.clazz
)

