package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.sync.postprocessing.ExportAdvanced

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_exportadvanced_settings_label(),
        field: 'json') {
    f.textarea(
            style: 'height:100px',
            checkMethod: 'post')
}
