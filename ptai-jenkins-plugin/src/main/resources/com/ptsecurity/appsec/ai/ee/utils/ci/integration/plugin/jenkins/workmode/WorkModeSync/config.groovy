package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync

import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.entry(
        title: _('onAstFailed'),
        field: 'onAstFailed') {
    f.select(style: 'width: 350px; ')
}

f.entry(
        title: _('onAstUnstable'),
        field: 'onAstUnstable') {
    f.select(style: 'width: 350px; ')
}

f.entry(
        title: _('reports'),
        help: descriptor.getHelpFile()) {

    f.repeatableHeteroProperty(
            field: 'reports',
            addCaption: _('reportAdd'))
}

