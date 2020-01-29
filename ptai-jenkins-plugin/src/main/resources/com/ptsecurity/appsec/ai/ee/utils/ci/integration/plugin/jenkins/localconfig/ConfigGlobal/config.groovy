package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.localconfig.ConfigGlobal

import lib.FormTagLib

def f = namespace(FormTagLib)

f.entry(
        title: _('configName'),
        field: 'configName') {
    f.select()
}
