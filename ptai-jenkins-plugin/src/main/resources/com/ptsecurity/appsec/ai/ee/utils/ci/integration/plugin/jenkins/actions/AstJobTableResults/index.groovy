package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobTableResults

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobTableResults
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.Utils.AbstractUI
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.Utils.Chart
import lib.LayoutTagLib

def l = namespace(LayoutTagLib)
def st = namespace("jelly:stapler")

def historyLength = 10

link(rel: 'stylesheet', href: "${rootURL}/plugin/ptai-jenkins-plugin/css/plugin.css")
script(src: "${rootURL}/plugin/ptai-jenkins-plugin/webjars/echarts/echarts.min.js")
script(src: "${rootURL}/plugin/ptai-jenkins-plugin/js/charts.js")

def createChartPlaceholder(int col, int row, int width, String prefix, String name, String title) {
    String style = "grid-area: ${row} / ${col} / span 1 / span ${width}; "

    // Need to add grid cells spacing if we have multiple charts in row
    String clazz = ""
    if (1 == width)
        clazz = 1 == col ? "ptai-chart-left" : "ptai-chart-right"
    div(style: style, class: clazz) {
        h3(title, class: "ptai-chart-header")
        div(
                id: "${prefix}-${name}",
                class: "graph-cursor-pointer ptai-chart ${1 == width ? "ptai-small-chart" : "ptai-big-chart"} ") {
        }
        div(id : "${prefix}-${name}-no-data", class: "h3 ptai-no-data") {
            text(Resources.i18n_ast_result_charts_message_nodata_label().toUpperCase())
        }
    }
}

def createChartPlaceholder(AstJobTableResults owner, Chart chart) {
    createChartPlaceholder(chart.col, chart.row, chart.width, owner.urlName, chart.name, chart.title)
}

class UI extends AbstractUI {
    UI(String prefix) {
        super(prefix)
    }

    @Override
    def addCharts(String prefix) {
        charts.add(new Chart(Chart.Type.LEVELS_HISTORY_BAR, 1, 1, 1, prefix, "levels-history-bar-chart", Resources.i18n_ast_result_charts_by_severity_label()))
        charts.add(new Chart(Chart.Type.APPROVAL_HISTORY_BAR, 2, 1, 1, prefix, "approval-history-bar-chart", Resources.i18n_ast_result_charts_by_approvalstatus_label()))
        charts.add(new Chart(Chart.Type.ISSUE_TYPE_HISTORY_BAR, 1, 2, 2, prefix, "issue-type-history-bar-chart", Resources.i18n_ast_result_charts_by_issuetype_no_rejected_label()))
        charts.add(new Chart(Chart.Type.SCAN_DURATION_HISTORY_BAR, 1, 3, 2, prefix, "scan-duration-history-bar-chart", Resources.i18n_ast_result_charts_by_scanduration_label()))
    }
}

UI ui = new UI((my as AstJobTableResults).urlName)

l.layout(title: "PT AI AST report") {
    l.side_panel() {
        st.include(page: "sidepanel.jelly", it: my.project)
    }
    l.main_panel() {
        h1(Resources.i18n_ast_result_charts_statistics_label())
        def latestResults = my.getLatestAstResults(historyLength)
        if (null == latestResults || latestResults.isEmpty()) {
            div(id: "${my.urlName}-no-data", class: "h2 ptai-no-data") {
                text("${Resources.i18n_ast_result_charts_message_noscans_label().toUpperCase()}")
            }
            return
        }
        h2(id: "h2", Resources.i18n_ast_result_charts_title_breakdown_label(), class: "ptai-chart-header")
        div(class: "ptai-main-content ptai-charts-div") {
            for (Chart chart : ui.charts) createChartPlaceholder(my, chart)
        }
        script """
            createBuildHistoryChart(
                "${ui.chartsMap[Chart.Type.LEVELS_HISTORY_BAR].divId}", 
                ${my.getLevelHistoryChart(historyLength)}, null);
            
            createBuildHistoryChart(
                "${ui.chartsMap[Chart.Type.APPROVAL_HISTORY_BAR].divId}", 
                ${my.getApprovalHistoryChart(historyLength)}, null);
            
            createBuildHistoryChart(
                "${ui.chartsMap[Chart.Type.ISSUE_TYPE_HISTORY_BAR].divId}", 
                ${my.getTypeHistoryChart(historyLength)}, null);

            createBuildHistoryChart(
                "${ui.chartsMap[Chart.Type.SCAN_DURATION_HISTORY_BAR].divId}", 
                ${my.getScanStageDurationHistoryChart(historyLength)}, null);
            
        """
    }
}

