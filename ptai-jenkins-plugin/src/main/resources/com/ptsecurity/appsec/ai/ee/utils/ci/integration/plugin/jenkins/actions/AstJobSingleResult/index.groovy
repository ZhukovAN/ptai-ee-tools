package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.Utils.AbstractUI
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.Utils.Chart
import lib.LayoutTagLib
import org.apache.commons.lang.StringUtils
import org.apache.commons.lang3.time.DurationFormatUtils

import java.time.Duration
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

def l = namespace(LayoutTagLib)
def st = namespace("jelly:stapler")

link(rel: 'stylesheet', href: "${rootURL}/plugin/ptai-jenkins-plugin/css/plugin.css")
script(src: "${rootURL}/plugin/ptai-jenkins-plugin/webjars/echarts/echarts.min.js")
script(src: "${rootURL}/plugin/ptai-jenkins-plugin/js/charts.js")

/**
 * Set AST settings table cell class in accordance with its coordinates. Like bold
 * line for left border in the leftmost cells etc.
 * @param x Table column number
 * @param y Table row number
 * @param w Table width to check if cell is a leftmost etc.
 * @param h Table height
 * @return Cell class
 */
static def astSettingsTableCellClass(int x, int y, int w, int h) {
    def clazz = "ptai-cell "
    // Set left border for leftmost cell
    if (0 == x) clazz += "ptai-cell-left "
    // ... and right for rightmost
    if (w - 1 == x) clazz += "ptai-cell-right "
    // The same for topmost
    if (0 == y) clazz += "ptai-cell-top "
    /// ... and lowermost
    if (h - 1 == y) clazz += "ptai-cell-bottom "

    return clazz
}

/**
 * Add table that holds AST settings
 * @param data Map that contains name : value pairs for AST settings
 * @return Table with AST settings
 */
def showAstSettingsTable(data, String color) {
    table(class: "ptai-main-content ptai-settings-table") {
        colgroup() {
            col(width: "300px")
        }
        tbody() {
            // For each map element create table cell with dynamically generated style that corresponds its position
            data.eachWithIndex{key, value, i ->
                tr() {
                    [0, 1].each { j ->
                        String cellClass = astSettingsTableCellClass(j, i, 2, data.size())
                        if (null != color) cellClass = cellClass.replaceAll("-cell", "-cell-" + color)
                        td(align: "left", class: cellClass) {
                            text(0 == j ? key : value)
                        }
                    }
                }
            }
        }
    }
}

/**
 * Add table that holds AST settings
 * @param data Map that contains name : value pairs for AST settings
 * @return Table with AST settings
 */
def showAstSettingsTable(data) {
    showAstSettingsTable(data, null)
}

def createChartPlaceholder(int col, int row, int width, String prefix, String name, String title) {
    String style = "grid-area: ${row} / ${col} / span 1 / span ${width}; "

    // Need to add grid cells spacing if we have multiple charts in row
    String clazz = ""
    if (1 == width)
        clazz = 1 == col ? "ptai-chart-left" : "ptai-chart-right"
    div(style: style, class: clazz) {
        h3(title)
        div(
                id: "${prefix}-${name}",
                class: "graph-cursor-pointer ptai-chart ${1 == width ? "ptai-small-chart" : "ptai-big-chart"} ") {
        }
        div(id : "${prefix}-${name}-no-data", class: "h3 ptai-no-data") {
            text(Resources.i18n_ast_result_charts_message_nodata_label().toUpperCase())
        }
    }
}

def createChartPlaceholder(AstJobSingleResult owner, Chart chart) {
    createChartPlaceholder(chart.col, chart.row, chart.width, owner.urlName, chart.name, chart.title)
}

class UI extends AbstractUI {
    UI(String prefix) {
        super(prefix)
    }

    @Override
    def addCharts(String prefix) {
        charts.add(new Chart(Chart.Type.ISSUE_LEVELS_BAR, 1, 1, 2, prefix, "levels-bar-chart", Resources.i18n_ast_result_charts_by_severity_no_rejected_label()))
        charts.add(new Chart(Chart.Type.ISSUE_CLASS_PIE, 1, 2, 1, prefix, "issue-class-pie-chart", Resources.i18n_ast_result_charts_by_issueclass_label()))
        charts.add(new Chart(Chart.Type.APPROVAL_STATUS_PIE, 2, 2, 1, prefix, "approval-status-pie-chart", Resources.i18n_ast_result_charts_by_approvalstatus_label()))
        charts.add(new Chart(Chart.Type.SUSPECTED_STATE_PIE, 1, 3, 1, prefix, "suspected-state-pie-chart", Resources.i18n_ast_result_charts_by_suspectedstatus_label()))
        charts.add(new Chart(Chart.Type.SCAN_MODE_PIE, 2, 3, 1, prefix, "scan-mode-pie-chart", Resources.i18n_ast_result_charts_by_scanmode_label()))
        charts.add(new Chart(Chart.Type.ISSUE_TYPE_BAR, 1, 4, 2, prefix, "issue-type-bar-chart", Resources.i18n_ast_result_charts_by_issuetype_no_rejected_label()))
    }
}

UI ui = new UI((my as AstJobSingleResult).urlName)

l.layout(title: Resources.i18n_ast_result_label()) {
    l.side_panel() {
        st.include(page: "sidepanel.jelly", from: my.run, it: my.run, optional: true)
    }

    l.main_panel() {
        def scanBriefDetailed = my.loadScanBriefDetailed()

        h1(Resources.i18n_ast_result_singlebuild_title_label())
        h2(Resources._i18n_ast_settings_label())

        def scanSettings = [:]
        scanSettings[Resources.i18n_ast_settings_base_projectname_label()] = "${scanBriefDetailed.projectName}"
        def url = scanBriefDetailed.scanSettings.url;
        if (null == url) url = Resources.i18n_misc_strings_empty();
        scanSettings[Resources.i18n_ast_settings_base_url_label()] = url
        scanSettings[Resources.i18n_ast_settings_base_programminglanguage_label()] = "${scanBriefDetailed.scanSettings.language}"
        scanSettings[Resources.i18n_ast_settings_mode_label()] = scanBriefDetailed.getUseAsyncScan()
                ? Resources.i18n_ast_settings_mode_asynchronous_label()
                : Resources.i18n_ast_settings_mode_synchronous_label()
        showAstSettingsTable(scanSettings)

        if (null != scanBriefDetailed.statistics) {
            def statistics = [:]
            ZonedDateTime scanDate = ZonedDateTime.parse(scanBriefDetailed.statistics.scanDateIso8601)
            scanDate = scanDate.withZoneSameInstant(ZoneId.systemDefault())
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yy HH:mm:ss")
            statistics[Resources.i18n_ast_result_statistics_startdatetime_label()] = "${scanDate.format(formatter)}"
            durationMs = Duration.parse(scanBriefDetailed.statistics.scanDurationIso8601).toMillis()
            statistics[Resources.i18n_ast_result_statistics_duration_label()] = "${DurationFormatUtils.formatDuration(durationMs, "H:mm:ss", true)}"
            showAstSettingsTable(statistics)
        }

        if (!scanBriefDetailed.getUseAsyncScan()) {
            def state = [:]
            String color = null
            if (scanBriefDetailed.getState() in [ScanBrief.State.ABORTED, ScanBrief.State.FAILED]) {
                color = "red"
                state["${Resources.i18n_ast_result_status_label()}"] = ScanBrief.State.ABORTED == scanBriefDetailed.getState()
                        ? Resources.i18n_ast_result_status_interrupted_label()
                        : Resources.i18n_ast_result_status_failed_label()
            } else
                state["${Resources.i18n_ast_result_status_label()}"] = Resources.i18n_ast_result_status_success_label()
            showAstSettingsTable(state, color)

            def policy = [:]
            if (Policy.State.REJECTED == scanBriefDetailed.getPolicyState()) {
                color = "red"
                policy["${Resources.i18n_ast_result_policy_label()}"] = Resources.i18n_ast_result_policy_failed_label()
            } else if (Policy.State.CONFIRMED == scanBriefDetailed.getPolicyState()) {
                color = "green"
                policy["${Resources.i18n_ast_result_policy_label()}"] = Resources.i18n_ast_result_policy_confirmed_label()
            } else {
                color = null
                policy["${Resources.i18n_ast_result_policy_label()}"] = Resources.i18n_ast_result_policy_none_label()
            }
            showAstSettingsTable(policy, color)
        }

        def versions = [:]
        if (StringUtils.isNotEmpty(scanBriefDetailed.ptaiServerUrl))
            versions[Resources.i18n_ast_settings_server_url_label()] = scanBriefDetailed.ptaiServerUrl
        versions[Resources.i18n_ast_result_statistics_server_version_label()] = scanBriefDetailed.ptaiServerVersion
        versions[Resources.i18n_ast_result_statistics_agent_version_label()] = scanBriefDetailed.ptaiAgentVersion
        showAstSettingsTable(versions)

        if (my.isEmpty()) return

        h2(Resources.i18n_ast_result_charts_title_breakdown_label())
        // Create main charts placeholder grid and initialize it with chart DIVs
        div(class: "ptai-main-content ptai-charts-div") {
            for (Chart chart : ui.charts) createChartPlaceholder(my, chart)
        }

        script """
            // Read / store big bar charts data and find widest Y-axis title width to shift all vertical axes to same position    
            var options = [];
            options["${Chart.Type.ISSUE_LEVELS_BAR.name()}"] = ${my.getVulnerabilityLevelDistribution()}
            options["${Chart.Type.ISSUE_TYPE_BAR.name()}"] = ${my.getVulnerabilityTypeDistribution()}
            // Get widest Y-axis title width
            var strings = options["${Chart.Type.ISSUE_LEVELS_BAR.name()}"].yAxis[0].data
                .concat(options["${Chart.Type.ISSUE_TYPE_BAR.name()}"].yAxis[0].data);
            var maxChartTextWidth = maxChartTextWidth(strings);
            
            createDistributionBarChart("${ui.chartsMap[Chart.Type.ISSUE_LEVELS_BAR].divId}", options["${Chart.Type.ISSUE_LEVELS_BAR.name()}"], maxChartTextWidth)
            createDistributionBarChart("${ui.chartsMap[Chart.Type.ISSUE_TYPE_BAR].divId}", options["${Chart.Type.ISSUE_TYPE_BAR.name()}"], maxChartTextWidth)
                 
            createDistributionPieChart(
                "${ui.chartsMap[Chart.Type.ISSUE_CLASS_PIE].divId}", 
                ${my.getVulnerabilityTypePie()});
            createDistributionPieChart(
                "${ui.chartsMap[Chart.Type.APPROVAL_STATUS_PIE].divId}", 
                ${my.getVulnerabilityApprovalStatePie()});
            createDistributionPieChart(
                "${ui.chartsMap[Chart.Type.SUSPECTED_STATE_PIE].divId}", 
                ${my.getVulnerabilitySuspectedPie()});
            createDistributionPieChart(
                "${ui.chartsMap[Chart.Type.SCAN_MODE_PIE].divId}", 
                ${my.getVulnerabilityScanModePie()});
        """
    }
}
