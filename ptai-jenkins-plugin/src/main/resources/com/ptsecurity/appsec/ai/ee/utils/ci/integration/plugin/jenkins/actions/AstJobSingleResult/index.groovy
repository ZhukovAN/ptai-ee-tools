package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult

import lib.FormTagLib
import lib.LayoutTagLib

import java.time.Duration
import org.apache.commons.lang3.time.DurationFormatUtils

import java.time.ZoneId
import java.time.LocalDateTime
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

def f = namespace(FormTagLib)
def l = namespace(LayoutTagLib)
def t = namespace('/lib/hudson')
def st = namespace("jelly:stapler")

l.layout(title: "PT AI AST report") {
    l.side_panel() {
        st.include(page: "sidepanel.jelly", from: my.run, it: my.run, optional: true)
    }

    l.main_panel() {
        h2("List of PT AI issues for this build")
        h3("Scan settings")
        table(id: "${my.urlName}-settings",
                style: "width: 95%; margin: 0 auto; min-width: 200px", bgcolor: "#ECECEC") {
            colgroup() {
                col(width: "250px")
            }
            tbody() {
                tr() {
                    td(align: "left", style: "padding-left: 20px; padding-top: 8px") {
                        text("Project")
                    }
                    td(align: "left", style: "font-weight:bold; padding-top: 8px") {
                        text("${my.scanResult.projectName}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px") {
                        text("Website address")
                    }
                    td(align: "left", style: "font-weight:bold") {
                        text("${my.scanResult.scanSettings.url}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px") {
                        text("Programming language")
                    }
                    td(align: "left", style: "font-weight:bold") {
                        text("${my.scanResult.scanSettings.language}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px; padding-top: 8px") {
                        text("Scan date / time")
                    }
                    ZonedDateTime scanDate = ZonedDateTime.parse(my.scanResult.statistic.scanDateIso8601)
                    scanDate = scanDate.withZoneSameInstant(ZoneId.systemDefault())
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yy HH:mm:ss");
                    td(align: "left", style: "font-weight:bold; padding-top: 8px") {
                        text("${scanDate.format(formatter)}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px") {
                        text("Scan duration")
                    }
                    durationMs = Duration.parse(my.scanResult.statistic.scanDurationIso8601).toMillis()
                    td(align: "left", style: "font-weight:bold") {
                        text("${DurationFormatUtils.formatDuration(durationMs, "H:mm:ss", true);}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px; padding-top: 8px") {
                        text("Server version")
                    }
                    td(align: "left", style: "font-weight:bold; padding-top: 8px") {
                        text("${my.scanResult.ptaiServerVersion}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px") {
                        text("Agent version")
                    }
                    td(align: "left", style: "font-weight:bold") {
                        text("${my.scanResult.ptaiAgentVersion}")
                    }
                }
            }
        }
        h3("Breakdown of vulnerabilities")
        h4("By severity")
        div(
                id: "${my.urlName}-level-chart",
                class: 'graph-cursor-pointer') {}
        h4("By type")
        div(
                id: "${my.urlName}-type-chart",
                class: 'graph-cursor-pointer',
                style: "width: 70%; margin: 0 auto; min-height: 200px; min-width: 200px; height: 645px;") {}

        script(src: "${rootURL}/plugin/ptai-jenkins-plugin/webjars/echarts/echarts.common.min.js")
        script(src: "${rootURL}/plugin/ptai-jenkins-plugin/js/charts.js")

        st.bind(var: "action", value: my)
        script """
            var ${my.urlName}Action = action
            var maxTypeWidth = 20
            const barHeight = 28
            const bottomMargin = 20
            const axisLabelMargin = 8
            const axisFontFamily = "verdana"
            const axisFontSize = "12px"
            const style = "width: 95%; margin: 0 auto; min-width: 200px; "

            ${my.urlName}Action.getTypeDistributionBar(function (response) {
                var data = response.responseJSON
                if (0 == data.yAxis.data.length) {
                    \$("${my.urlName}-type-chart").setAttribute("style",style + "background-color: red")
                    \$("${my.urlName}-type-chart").innerHTML = "style"
                    return;
                }
                data.tooltip = { trigger: 'axis', axisPointer: { type: 'shadow' } }
                data.xAxis.minInterval = 1
                data.yAxis.axisLabel = { fontSize: axisFontSize, fontFamily: axisFontFamily, margin: axisLabelMargin } 
                maxTypeWidth = maxTextWidth(data.yAxis.data, axisFontSize + " " + axisFontFamily) + axisLabelMargin
                data.grid = { left: maxTypeWidth + "px", top: "0px", bottom: bottomMargin + "px" }
                divHeight = data.yAxis.data.length * barHeight + bottomMargin
                \$("${my.urlName}-type-chart").setAttribute("style",style + "height: " + divHeight + "px");
                renderTrendChart("${my.urlName}-type-chart", data)
                
                ${my.urlName}Action.getSeverityDistributionBar(function (response) {
                    var data = response.responseJSON
                    data.tooltip = { trigger: 'axis', axisPointer: { type: 'shadow' } }
                    data.xAxis.minInterval = 1
                    data.yAxis.axisLabel = { fontSize: axisFontSize, fontFamily: axisFontFamily, margin: axisLabelMargin }
                    data.grid = { left: maxTypeWidth + "px", top: "0px", bottom: bottomMargin + "px" }
                    divHeight = data.yAxis.data.length * barHeight + bottomMargin
                    \$("${my.urlName}-level-chart").setAttribute("style",style + "height: " + divHeight + "px");
                    renderTrendChart("${my.urlName}-level-chart", data)
                });
            });
        """
    }
}
