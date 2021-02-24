package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.scansettings.ScanSettingsManual

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(title: _("jsonSettings"), field: "jsonSettings") {
    f.textarea(
            style: 'height:100px',
            checkMethod: 'post')
}

f.block() {
    f.validateButton(
            title: _('testJsonSettings'),
            progress: _('testJsonSettingsProgress'),
            method: 'testJsonSettings',
            with: 'jsonSettings'
    )
}

f.entry(title: _("jsonPolicy"), field: "jsonPolicy") {
    f.textarea(
            style: 'height:100px',
            checkMethod: 'post')
}

f.block() {
    f.validateButton(
            title: _('testJsonPolicy'),
            progress: _('testJsonPolicyProgress'),
            method: 'testJsonPolicy',
            with: 'jsonPolicy'
    )
}

