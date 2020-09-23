package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.CredentialsImpl

def f = namespace(lib.FormTagLib);
def c = namespace(lib.CredentialsTagLib)
def st = namespace("jelly:stapler")

f.entry(
        title: _('token'),
        field: 'token') {
    f.password()
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