package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync

import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.entry(
        title: _('failIfFailed'),
        field: 'failIfFailed') {
    f.checkbox(
            name: 'failIfFailed',
            default: true
    )
}

f.entry(
        title: _('failIfUnstable'),
        field: 'failIfUnstable',
        default: 'true') {
    f.checkbox()
}

f.entry(
        title: _('reports'),
        help: descriptor.getHelpFile()) {

    f.repeatableHeteroProperty(
            field: 'reports',
            addCaption: _('reportAdd'))
}

