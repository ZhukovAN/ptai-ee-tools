package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.credentials.SlimCredentialsImpl

def f = namespace(lib.FormTagLib);
def c = namespace(lib.CredentialsTagLib)
def st = namespace("jelly:stapler")

f.entry(
        title: _('userName'),
        field: 'userName') {
    f.textbox()
}

f.entry(
        title: _('password'),
        field: 'password') {
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