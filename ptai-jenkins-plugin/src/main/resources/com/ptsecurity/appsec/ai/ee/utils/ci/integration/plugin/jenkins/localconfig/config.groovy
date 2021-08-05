package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig

def f = namespace(lib.FormTagLib);
def c = namespace(lib.CredentialsTagLib)

f.entry(title: _("configName"), field: "configName") {
    f.textbox()
}

f.property(
        field: "legacyServerSettings"
)

