package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.Data

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: _('fileName'),
        field: 'fileName') {
    f.textbox()
}

f.entry(
        title: _('format'),
        field: 'format') {
    f.select(style: 'width: 120px;')
}

f.entry(
        title: _('locale'),
        field: 'locale') {
    f.select(
            style: 'width: 120px;',
            default: descriptor.getDefaultLocale(),
    )
}

f.advanced() {
    f.entry(
            title: _('filter'),
            field: 'filter') {
        f.textarea(
                style: 'height:100px',
                checkMethod: 'post')
    }
}