package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.dropdownDescriptorSelector(
        title: _('scanSettings'),
        field: 'scanSettings',
        default: descriptor.getDefaultScanSettingsDescriptor(),
        descriptors: descriptor.getScanSettingsDescriptors())

f.dropdownDescriptorSelector(
        title: _('config'),
        field: 'config',
        default: descriptor.getDefaultConfigDescriptor(),
        descriptors: descriptor.getConfigDescriptors()
)

f.dropdownDescriptorSelector(
        title: _('workMode'),
        field: 'workMode',
        default: descriptor.getDefaultWorkModeDescriptor(),
        descriptors: descriptor.getWorkModeDescriptors())

f.entry(
        title: _('transfers')) {
    set('descriptor', descriptor.transferDescriptor)
    f.repeatable(
            var: 'instance',
            items: instance?.transfers,
            name: 'transfers',
            minimum: '1',
            // header: _('transfer'),
            add: _('transferAdd')) {
        table(
                width: '100%',
                padding: '0'
        ) {
            st.include(
                    page: 'config.groovy',
                    class: descriptor?.clazz
            )
            f.entry(
                    title: '') {
                div(align: 'right', class: 'show-if-not-only') {
                    f.repeatableDeleteButton(
                            value: _('transferDelete')
                    )
                }
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

    f.entry(
            title: _('fullScanMode'),
            field: 'fullScanMode',
            default: 'false') {
        f.checkbox()
    }

    f.entry(
            title: _('verbose'),
            field: 'verbose',
            default: 'false') {
        f.checkbox()
    }
}
