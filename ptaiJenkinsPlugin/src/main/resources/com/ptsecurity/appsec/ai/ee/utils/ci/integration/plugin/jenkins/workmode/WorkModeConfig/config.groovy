package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeConfig

def f = namespace(lib.FormTagLib);

f.entry(
        title: _('configName'),
        field: 'configName') {
    f.select()
}

f.entry(
        title: _('projectName'),
        field: 'projectName') {
    f.textbox()
}

