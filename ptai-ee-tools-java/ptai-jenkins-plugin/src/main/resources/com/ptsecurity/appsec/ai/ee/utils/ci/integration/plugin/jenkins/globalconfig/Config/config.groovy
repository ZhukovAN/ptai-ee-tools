package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig.Config

import lib.CredentialsTagLib
import lib.FormTagLib

def f = namespace(FormTagLib)
def c = namespace(CredentialsTagLib)

f.entry(title: _("configName"), field: "configName") {
    f.textbox()
}

f.property(
        field: "serverSettings"
)


