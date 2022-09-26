package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.Plugin

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings
import org.apache.commons.lang3.StringUtils

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
            def defaultValue = settingInfo.getDefaultValue()
            if (null == defaultValue || (AdvancedSettings.SettingType.STRING == settingInfo.type && StringUtils.isEmpty(defaultValue.toString())))
                defaultValue = Resources.i18n_misc_strings_empty()
            text("Default value: " + defaultValue)
        }
    }
}
