package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib
import lib.LayoutTagLib

import java.time.Duration
import org.apache.commons.lang3.time.DurationFormatUtils

import java.time.ZoneId
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
        def scanBriefDetailed = my.getScanBriefDetailed()

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
                        text("${scanBriefDetailed.projectName}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px") {
                        text("Website address")
                    }
                    td(align: "left", style: "font-weight:bold") {
                        text("${scanBriefDetailed.scanSettings.url}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px") {
                        text("Programming language")
                    }
                    td(align: "left", style: "font-weight:bold") {
                        text("${scanBriefDetailed.scanSettings.language}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px; padding-top: 8px") {
                        text("Scan date / time")
                    }
                    ZonedDateTime scanDate = ZonedDateTime.parse(scanBriefDetailed.statistic.scanDateIso8601)
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
                    durationMs = Duration.parse(scanBriefDetailed.statistic.scanDurationIso8601).toMillis()
                    td(align: "left", style: "font-weight:bold") {
                        text("${DurationFormatUtils.formatDuration(durationMs, "H:mm:ss", true);}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px; padding-top: 8px") {
                        text("Server version")
                    }
                    td(align: "left", style: "font-weight:bold; padding-top: 8px") {
                        text("${scanBriefDetailed.ptaiServerVersion}")
                    }
                }
                tr() {
                    td(align: "left", style: "padding-left: 20px") {
                        text("Agent version")
                    }
                    td(align: "left", style: "font-weight:bold") {
                        text("${scanBriefDetailed.ptaiAgentVersion}")
                    }
                }
            }
        }
        if (ScanBrief.State.DONE == scanBriefDetailed.state || ScanBrief.State.ABORTED == scanBriefDetailed.state) {
            h3("Breakdown of vulnerabilities")
            h4("By severity")
            div(
                    id: "${my.urlName}-level-chart",
                    class: 'graph-cursor-pointer',
                    style: "width: 70%; margin: 0 auto; min-height: 200px; min-width: 200px; height: 645px;") {}
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
    
                // Map vulnerability level to its localized title, absolute value and color
                var levelAttrs = {
                    ${BaseIssue.Level.HIGH.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_high()}',
                        itemColor: '#f57962', 
                        value: ${BaseIssue.Level.HIGH.value}
                    },
                    ${BaseIssue.Level.MEDIUM.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_medium()}',
                        itemColor: '#f9ad37', 
                        value: ${BaseIssue.Level.MEDIUM.value}
                    },
                    ${BaseIssue.Level.LOW.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_low()}', 
                        itemColor: '#66cc99', 
                        value: ${BaseIssue.Level.LOW.value}
                    },
                    ${BaseIssue.Level.POTENTIAL.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_potential()}', 
                        itemColor: '#8cb5e1', 
                        value: ${BaseIssue.Level.POTENTIAL.value}
                    }
                }
    
                var maxTypeWidth = 20
                const barHeight = 28
                const bottomMargin = 20
                const axisLabelMargin = 8
                const axisFontFamily = "verdana"
                const axisFontSize = "12px"
                const style = "width: 95%; margin: 0 auto; min-width: 200px; "
    
                ${my.urlName}Action.getScanBriefDetailedJson(function (response) {
                    var data = response.responseJSON
                    var dataSet = [];
                    data.details.chartData.baseIssueDistributionData
                        .filter(function(value) {
                            return value.approvalState != 'DISCARD'
                        })
                        .reduce(function(res, value) {
                            if (!res[value.title]) {
                                res[value.title] = { title: value.title, level: value.level, count: 0 };
                                dataSet.push(res[value.title])
                            }
                            res[value.title].count += value.count;
                            return res;
                        }, {});
                    dataSet.sort(function(a, b) {
                        if (levelAttrs[a.level].value == levelAttrs[b.level].value)
                            return a.count - b.count;
                        return levelAttrs[a.level].value - levelAttrs[b.level].value;
                    });
                    var option = {
                        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
                        xAxis: { type: 'value', minInterval: 1 },
                        yAxis: { type: 'category', data: [] },
                        series: [{ type: 'bar', name: 'Quantity', data: [] }]
                    };
                    dataSet.forEach(function(item) {
                        option.yAxis.data.push(item.title)
                        var dataItem = {
                            value: item.count,
                            itemStyle: { color: levelAttrs[item.level].itemColor }
                        };
                        option.series[0].data.push(dataItem);
                    });
                    maxTypeWidth = maxTextWidth(option.yAxis.data, axisFontSize + " " + axisFontFamily) + axisLabelMargin
                    option.grid = { left: maxTypeWidth + "px", top: "0px", bottom: bottomMargin + "px" }
                    divHeight = option.yAxis.data.length * barHeight + bottomMargin
                    \$("${my.urlName}-type-chart").setAttribute("style",style + "height: " + divHeight + "px");                    
                    renderChart("${my.urlName}-type-chart", option)
                       
                    hashSet = data.details.chartData.baseIssueDistributionData
                        .filter(function(value) {
                            return value.approvalState != 'DISCARD'
                        })
                        .reduce(function(res, value) {
                            if (!res[value.level]) {
                                res[value.level] = { level: value.level, count: 0 };
                            }
                            res[value.level].count += value.count;
                            return res;
                        }, {});
                    option = {
                        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
                        xAxis: { type: 'value', minInterval: 1 },
                        yAxis: { type: 'category', inverse: true, data: [] },
                        series: [{ type: 'bar', name: 'Quantity', data: [] }]
                    };
                    for (var level in levelAttrs) {
                        if (undefined === hashSet[level] || 0 == hashSet[level].count) continue;
                        option.yAxis.data.push(levelAttrs[level].title)
                        var item = {
                            value: hashSet[level].count,
                            itemStyle: { color: levelAttrs[level].itemColor }
                        };
                        option.series[0].data.push(item);
                    }
                    option.grid = { left: maxTypeWidth + "px", top: "0px", bottom: bottomMargin + "px" }
                    divHeight = option.yAxis.data.length * barHeight + bottomMargin
                    \$("${my.urlName}-level-chart").setAttribute("style",style + "height: " + divHeight + "px");
                    renderChart("${my.urlName}-level-chart", option)
                });
            """
        } else {

        }
    }
}
