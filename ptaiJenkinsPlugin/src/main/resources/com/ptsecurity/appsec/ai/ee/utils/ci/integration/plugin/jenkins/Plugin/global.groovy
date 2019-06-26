package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin

import lib.FormTagLib

def f = namespace(FormTagLib);

f.section(
        title: descriptor.displayName) {
    f.entry(
            title: _('configs'),
            help: descriptor.getHelpFile()) {

        f.repeatableHeteroProperty(
                field: 'globalConfigs',
                hasHeader: 'true',
                addCaption: _('addGlobalConfigButton'))
    }
}
