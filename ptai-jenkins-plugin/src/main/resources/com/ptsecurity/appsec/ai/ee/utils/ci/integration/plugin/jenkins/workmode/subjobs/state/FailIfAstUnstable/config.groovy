package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.state.FailIfAstUnstable

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_subjob_state_processerrors_action_label(),
        field: 'onAstUnstable') {
    f.select(
            style: 'width: 420px; ',
            default: descriptor.getDefaultOnAstUnstable()
    )
}
