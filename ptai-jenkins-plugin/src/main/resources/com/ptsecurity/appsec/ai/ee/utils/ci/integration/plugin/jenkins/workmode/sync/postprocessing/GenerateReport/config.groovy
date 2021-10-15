package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.Report

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_generatereport_file_label(),
        field: 'fileName') {
    f.textbox()
}

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_generatereport_template_label(),
        field: 'template') {
    f.textbox(
            default: descriptor.getDefaultTemplate(),
    )
}

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_generatereport_format_label(),
        field: 'format') {
    f.select(style: 'width: 120px;')
}

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_generatereport_locale_label(),
        field: 'locale') {
    f.select(
            style: 'width: 120px;',
            default: descriptor.getDefaultLocale().name(),
    )
}

f.advanced() {
    f.entry(
            title: Resources.i18n_ast_settings_mode_synchronous_postprocessing_step_generatereport_filter_label(),
            field: 'filter') {
        f.textarea(
                style: 'height:100px',
                checkMethod: 'post')
    }
}