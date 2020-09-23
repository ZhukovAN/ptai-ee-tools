package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync

import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.entry(
        title: _('failIfFailed'),
        field: 'failIfFailed') {
    f.checkbox(
            name: 'failIfFailed',
            default: true
    )
}

f.entry(
        title: _('failIfUnstable'),
        field: 'failIfUnstable',
        default: 'true') {
    f.checkbox()
}

f.entry(
        title: _('reports')) {
    set('descriptor', descriptor.reportDescriptor)
    f.repeatable(
            var: 'instance',
            items: instance?.reports,
            name: 'reports',
            minimum: '0',
            header: _('report'),
            add: _('reportAdd')) {
        table(width: '100%', padding: '0') {
            st.include(
                    page: 'config.groovy',
                    class: descriptor?.clazz
            )
            f.entry(title: '') {
                div(align: 'right') {
                    f.repeatableDeleteButton(
                            value: _('reportDelete')
                    )
                }
            }
        }
    }
}

