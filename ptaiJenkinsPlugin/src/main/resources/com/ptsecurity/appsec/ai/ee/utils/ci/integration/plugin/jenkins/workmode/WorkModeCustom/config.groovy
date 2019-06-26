package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.PtaiConfig

def f = namespace(lib.FormTagLib);

f.property(
        field: "serverSettings"
)

f.entry(
        title: _('projectName'),
        field: 'projectName') {
    f.textbox()
}

