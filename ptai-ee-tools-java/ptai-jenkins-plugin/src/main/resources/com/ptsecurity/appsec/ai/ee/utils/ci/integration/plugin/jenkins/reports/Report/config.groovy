package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.Report

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: _('fileName'),
        field: 'fileName') {
    f.textbox()
}

f.entry(
        title: _('template'),
        field: 'template') {
    f.textbox()
}

f.entry(
        title: _('format'),
        field: 'format') {
    f.select()
}

f.entry(
        title: _('locale'),
        field: 'locale') {
    f.select()
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