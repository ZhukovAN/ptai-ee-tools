package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.sync.postprocessing.ExportData

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_exportdata_file_label(),
        field: 'fileName') {
    f.textbox()
}

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_exportdata_format_label(),
        field: 'format') {
    f.select(style: 'width: 120px;')
}

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_exportdata_locale_label(),
        field: 'locale') {
    f.select(
            style: 'width: 120px;',
            default: descriptor.getDefaultLocale(),
    )
}

f.advanced() {
    f.entry(
            title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_exportdata_filter_label(),
            field: 'filter') {
        f.textarea(
                style: 'height:100px',
                checkMethod: 'post')
    }
}