package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports.Json

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: _('json'),
        field: 'json') {
    f.textarea(
            style: 'height:100px',
            checkMethod: 'post')
}
