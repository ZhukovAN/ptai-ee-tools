package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.subjobs.export.Report

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_file_label(),
        field: 'fileName') {
    f.textbox()
}

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_template_label(),
        field: 'template') {
    f.textbox(
            default: descriptor.getDefaultTemplate()
    )
}

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_includedfd_label(),
        field: 'includeDfd',
        default: 'true') {
    f.checkbox()
}

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_includeglossary_label(),
        field: 'includeGlossary',
        default: 'true') {
    f.checkbox()
}

f.advanced() {
    f.entry(
            title: Resources.i18n_ast_settings_mode_synchronous_subjob_export_report_filter_label(),
            field: 'filter') {
        f.textarea(
                style: 'height:100px',
                checkMethod: 'post')
    }
}