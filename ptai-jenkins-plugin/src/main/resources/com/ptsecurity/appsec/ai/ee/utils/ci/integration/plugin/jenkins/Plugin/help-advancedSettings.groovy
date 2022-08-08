package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings

text(Resources.i18n_ast_settings_advanced_hint())
ul() {
    for (AdvancedSettings.SettingInfo settingInfo : AdvancedSettings.SettingInfo.values()) {
        li() {
            b() {
                tt(settingInfo.name)
            }
            br()
            text(settingInfo.getDescriptionFunction().get())
            br()
            text("Default value: " + settingInfo.getDefaultValue())
        }
    }
}
