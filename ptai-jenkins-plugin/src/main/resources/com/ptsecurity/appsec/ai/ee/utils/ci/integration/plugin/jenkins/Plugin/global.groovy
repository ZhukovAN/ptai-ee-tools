package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib);

f.section(
        title: descriptor.displayName) {
    f.entry(
            title: _('configs'),
            help: descriptor.getHelpFile()) {

        f.repeatableProperty(
                field: 'globalConfigs',
                hasHeader: 'true',
                addCaption: _('addGlobalConfigButton')) {
            f.entry {
                div(align: "right") {
                    f.repeatableDeleteButton()
                }
            }
        }
    }

    f.advanced() {
        f.entry(
                title: Resources.i18n_ast_settings_advanced_label(),
                field: 'advancedSettings') {
            f.textarea(
                    style: 'height:100px',
                    checkMethod: 'post')
        }
    }
}
