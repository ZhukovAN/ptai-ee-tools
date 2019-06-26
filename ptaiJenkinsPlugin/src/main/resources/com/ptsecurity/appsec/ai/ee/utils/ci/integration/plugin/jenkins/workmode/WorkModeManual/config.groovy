package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.PtaiConfig

def f = namespace(lib.FormTagLib);
def c = namespace(lib.CredentialsTagLib)

f.entry(title: _("jsonSettings"), field: "jsonSettings") {
    f.textarea()
}
