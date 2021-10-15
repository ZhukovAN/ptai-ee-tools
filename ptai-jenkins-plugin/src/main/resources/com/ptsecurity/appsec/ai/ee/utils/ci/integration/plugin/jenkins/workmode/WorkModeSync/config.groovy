package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")
/*
f.entry(
        title: _('onAstFailed'),
        field: 'onAstFailed') {
    f.select(style: 'width: 420px; ')
}

f.entry(
        title: _('onAstUnstable'),
        field: 'onAstUnstable') {
    f.select(style: 'width: 420px; ')
}

f.entry(
        title: _('reports'),
        help: descriptor.getHelpFile()) {

    f.repeatableHeteroProperty(
            field: 'reports',
            addCaption: _('reportAdd'))
}
*/
f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_list_label(),
        help: descriptor.getHelpFile()) {

    f.repeatableHeteroProperty(
            field: 'afterSteps',
            hasHeader: true,
            addCaption: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_add_label())
}
