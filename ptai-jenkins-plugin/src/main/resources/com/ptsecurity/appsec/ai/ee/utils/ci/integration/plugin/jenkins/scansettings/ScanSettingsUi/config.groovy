package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsUi

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: _('projectName'),
        field: 'projectName') {
    f.textbox()
}
