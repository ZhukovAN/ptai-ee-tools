package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.workmode.WorkModeSync

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.entry(
        title: Resources.i18n_ast_settings_mode_synchronous_subjob_list_label(),
        help: descriptor.getHelpFile()) {

    f.repeatableHeteroProperty(
            field: 'subJobs',
            hasHeader: true,
            addCaption: Resources.i18n_ast_settings_mode_synchronous_subjob_add_label())
}
