package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Transfer

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        // title: _('includes'),
        title: descriptor.transferDefaults.patternSeparator,
        field: 'includes',
        default: descriptor.clazz) {
    f.textbox()
}

f.entry(
        title: _('removePrefix'),
        field: 'removePrefix') {
    f.textbox()
}
f.advanced() {
    f.entry(
            title: _('excludes'),
            field: 'excludes') {
        f.textbox()
    }

    f.entry(
            title: _('patternSeparator'),
            field: 'patternSeparator') {
        f.textbox()
    }

    f.entry(
            title: _('useDefaultExcludes'),
            field: 'useDefaultExcludes') {
        f.checkbox()
    }

    f.entry(
            title: _('flatten'),
            field: 'flatten',
            default: 'true') {
        f.checkbox()
    }
}
