package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(title: _("jsonSettings"), field: "jsonSettings") {
    f.textarea(
            style: 'height:100px',
            checkMethod: 'post')
}

f.entry(title: _("jsonPolicy"), field: "jsonPolicy") {
    f.textarea(
            style: 'height:100px',
            checkMethod: 'post')
}
