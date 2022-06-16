package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.descriptor.PluginDescriptor
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper
import jenkins.model.Jenkins
import lib.FormTagLib
import lib.LayoutTagLib
import org.apache.commons.lang3.time.DurationFormatUtils

import java.awt.Color
import java.time.Duration
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.jar.Attributes
import java.util.jar.Manifest

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel.LEVEL_COLORS

def f = namespace(FormTagLib)
def l = namespace(LayoutTagLib)
def t = namespace('/lib/hudson')
def st = namespace("jelly:stapler")

t.summary(icon: my.getIconFileName()) {
    def scanBriefDetailed = my.getScanBriefDetailed()
    div() {
        b(Resources.i18n_ast_plugin_label() + " (")
        if (ScanBrief.ApiVersion.V36 == scanBriefDetailed.apiVersion) {
            a(href: "ptai://navigation/show?project=" + scanBriefDetailed.projectId) {
                text(_("project.open.viewer.label"))
            }
        } else {
            a(href: scanBriefDetailed.ptaiServerUrl + "/ui/projects/" + scanBriefDetailed.projectId + "/scan/" + scanBriefDetailed.id) {
                text(_("project.open.ui.label"))
            }
        }
        text(")")
        if (scanBriefDetailed.getUseAsyncScan()) {
            ul() {
                li(Resources.i18n_ast_settings_mode_asynchronous_label())
            }
        } else {
            def state = ScanBrief.State.ABORTED == scanBriefDetailed.getState()
                    ? Resources.i18n_ast_result_status_interrupted_label()
                    : ScanBrief.State.FAILED == scanBriefDetailed.getState()
                    ? Resources.i18n_ast_result_status_failed_label()
                    : ScanBrief.State.DONE == scanBriefDetailed.getState()
                    ? Resources.i18n_ast_result_status_success_label()
                    : "Unknown state: " + scanBriefDetailed.getState()
            state = Resources.i18n_ast_result_status_label() + ": " + state
            def policyState = Policy.State.REJECTED == scanBriefDetailed.getPolicyState()
                    ? Resources.i18n_ast_result_policy_failed_label()
                    : Policy.State.CONFIRMED == scanBriefDetailed.getPolicyState()
                    ? Resources.i18n_ast_result_policy_confirmed_label()
                    : Resources.i18n_ast_result_policy_none_label()
            policyState = Resources.i18n_ast_result_policy_label() + ": " + policyState
            ul() {
                li(state)
                li(policyState)
            }
        }
    }
}