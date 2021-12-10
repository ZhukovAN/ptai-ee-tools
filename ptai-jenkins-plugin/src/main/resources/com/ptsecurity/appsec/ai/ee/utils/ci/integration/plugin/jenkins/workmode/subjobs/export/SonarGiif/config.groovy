package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export.SonarGiif

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_file_label(),
        field: 'fileName') {
    f.textbox()
}

f.advanced() {
    f.entry(
            title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_sonargiif_filter_label(),
            field: 'filter') {
        f.textarea(
                style: 'height:100px',
                checkMethod: 'post')
    }
}