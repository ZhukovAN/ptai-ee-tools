package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.sync.postprocessing.FailIfAstUnstable

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_processerrors_label(),
        field: 'onAstUnstable') {
    f.select(style: 'width: 420px; ')
}
