package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue
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

        def styleFirstTd = 'padding-top: 0px; padding-bottom: 0px; padding-right: 0px; '
        def styleSecondTd = 'padding-top: 0px; padding-bottom: 0px; padding-left: 0px; padding-right: 0px; font-weight:bold; background-color: #f8f8f8; '
        def styleFirstDiv = 'border-left-width: 4px; border-left-style: solid; border-color: rgb(116, 116, 116); padding-left: 20px; margin-left: 2px; background-color: #f8f8f8; '
        def styleSecondDiv = 'border-right-width: 1px; border-right-style: solid; border-color: rgb(230, 230, 230); background-color: #f8f8f8; '

        h1(_("result.title"))
        h2(_("scan.settings.title"))
        table(style: "width: 95%; margin: 0 auto; min-width: 200px; border-collapse: collapse; margin-top: 10px; ") {
            colgroup() {
                col(width: "300px")
            }
            tbody() {
                tr() {
                    td(align: "left", style: "${styleFirstTd}") {
                        div(style: "${styleFirstDiv}padding-top: 8px; border-top-width: 1px; border-top-style: solid; border-top-color: rgb(230, 230, 230); ") {
                            text(_("scan.settings.project"))
                        }
                    }
                    td(align: "left", style: "${styleSecondTd}") {
                        div(style: "${styleSecondDiv}padding-top: 8px; border-top-width: 1px; border-top-style: solid; border-top-color: rgb(230, 230, 230); ") {
                            text("${scanBriefDetailed.projectName}")
                        }
                    }
                }
                tr() {
                    td(align: "left", style: "${styleFirstTd}") {
                        div(style: "${styleFirstDiv}") {
                            text(_("scan.settings.url"))
                        }
                    }
                    td(align: "left", style: "${styleSecondTd}") {
                        div(style: "${styleSecondDiv}") {
                            text("${scanBriefDetailed.scanSettings.url}")
                        }
                    }
                }
                tr() {
                    td(align: "left", style: "${styleFirstTd}") {
                        div(style: "${styleFirstDiv}padding-bottom: 8px; border-bottom-width: 1px; border-bottom-style: solid; border-bottom-color: rgb(230, 230, 230); ") {
                            text(_("scan.settings.language"))
                        }
                    }
                    td(align: "left", style: "${styleSecondTd}") {
                        div(style: "${styleSecondDiv}padding-bottom: 8px; border-bottom-width: 1px; border-bottom-style: solid; border-bottom-color: rgb(230, 230, 230); ") {
                            text("${scanBriefDetailed.scanSettings.language}")
                        }
                    }
                }
            }
        }
        table(style: "width: 95%; margin: 0 auto; min-width: 200px; border-collapse: collapse; margin-top: 10px; ") {
            colgroup() {
                col(width: "300px")
            }
            tbody() {
                tr() {
                    td(align: "left", style: "${styleFirstTd}") {
                        div(style: "${styleFirstDiv}padding-top: 8px; border-top-width: 1px; border-top-style: solid; border-top-color: rgb(230, 230, 230); ") {
                            text(_("scan.timestamp"))
                        }
                    }
                    ZonedDateTime scanDate = ZonedDateTime.parse(scanBriefDetailed.statistic.scanDateIso8601)
                    scanDate = scanDate.withZoneSameInstant(ZoneId.systemDefault())
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yy HH:mm:ss");
                    td(align: "left", style: "${styleSecondTd}") {
                        div(style: "${styleSecondDiv}padding-top: 8px; border-top-width: 1px; border-top-style: solid; border-top-color: rgb(230, 230, 230); ") {
                            text("${scanDate.format(formatter)}")
                        }
                    }
                }
                tr() {
                    td(align: "left", style: "${styleFirstTd}") {
                        div(style: "${styleFirstDiv}padding-bottom: 8px; border-bottom-width: 1px; border-bottom-style: solid; border-bottom-color: rgb(230, 230, 230); ") {
                            text(_("scan.duration"))
                        }
                    }
                    durationMs = Duration.parse(scanBriefDetailed.statistic.scanDurationIso8601).toMillis()
                    td(align: "left", style: "${styleSecondTd}") {
                        div(style: "${styleSecondDiv}padding-bottom: 8px; border-bottom-width: 1px; border-bottom-style: solid; border-bottom-color: rgb(230, 230, 230); ") {
                            text("${DurationFormatUtils.formatDuration(durationMs, "H:mm:ss", true);}")
                        }
                    }
                }
            }
        }
        table(style: "width: 95%; margin: 0 auto; min-width: 200px; border-collapse: collapse; margin-top: 10px; ") {
            colgroup() {
                col(width: "300px")
            }
            tbody() {
                tr() {
                    td(align: "left", style: "${styleFirstTd}") {
                        div(style: "${styleFirstDiv}padding-top: 8px; border-top-width: 1px; border-top-style: solid; border-top-color: rgb(230, 230, 230); ") {
                            text(_("environment.server.version"))
                        }
                    }
                    td(align: "left", style: "${styleSecondTd}") {
                        div(style: "${styleSecondDiv}padding-top: 8px; border-top-width: 1px; border-top-style: solid; border-top-color: rgb(230, 230, 230); ") {
                            text("${scanBriefDetailed.ptaiServerVersion}")
                        }
                    }
                }
                tr() {
                    td(align: "left", style: "${styleFirstTd}") {
                        div(style: "${styleFirstDiv}padding-bottom: 8px; border-bottom-width: 1px; border-bottom-style: solid; border-bottom-color: rgb(230, 230, 230); ") {
                            text(_("environment.agent.version"))
                        }
                    }
                    td(align: "left", style: "${styleSecondTd}") {
                        div(style: "${styleSecondDiv}padding-bottom: 8px; border-bottom-width: 1px; border-bottom-style: solid; border-bottom-color: rgb(230, 230, 230); ") {
                            text("${scanBriefDetailed.ptaiAgentVersion}")
                        }
                    }
                }
            }
        }
        if (!my.isEmpty()) {
            h2(_("result.breakdown.title"))
            table(style: "width: 95%; margin: 0 auto; min-width: 200px; border-collapse: collapse; ") {
                colgroup() {
                    col(width: "50%")
                    col(width: "50%")
                }
                tbody() {
                    tr() {
                        td(style: "margin-left: 0px; margin-right: 0px; padding-right: 0px; ", colspan: "2") {
                            h3(_("result.breakdown.level.title"))
                            div(
                                    id: "${my.urlName}-level-chart",
                                    class: 'graph-cursor-pointer') {}
                        }
                    }
                    tr() {
                        td(style: "margin-left: 0px; margin-right: 16px; ") {
                            h3(_("result.breakdown.class.title"))
                            div(
                                    id: "${my.urlName}-class-pie-chart",
                                    class: 'graph-cursor-pointer; ') {}
                        }
                        td(style: "margin-left: 0px; margin-right: 0px; ") {
                            h3(_("result.breakdown.approvalstate.title"))
                            div(
                                    id: "${my.urlName}-approval-state-pie-chart",
                                    class: 'graph-cursor-pointer; ') {}
                        }
                    }
                    tr() {
                        td(style: "margin-left: 0px; margin-right: 16px; ") {
                            h3(_("result.breakdown.suspected.title"))
                            div(
                                    id: "${my.urlName}-suspected-state-pie-chart",
                                    class: 'graph-cursor-pointer; ') {}
                        }
                        td(style: "margin-left: 0px; margin-right: 0px; ") {
                            h3(_("result.breakdown.scanmode.title"))
                            div(
                                    id: "${my.urlName}-scan-mode-pie-chart",
                                    class: 'graph-cursor-pointer; ') {}
                        }
                    }
                    tr() {
                        td(style: "margin-left: 0px; margin-right: 0px; ", colspan: "2") {
                            h3(_("result.breakdown.type.title"))
                            div(
                                    id: "${my.urlName}-type-chart",
                                    class: 'graph-cursor-pointer') {}
                        }
                    }
                }
            }

            script(src: "${rootURL}/plugin/ptai-jenkins-plugin/webjars/echarts/echarts.min.js")
            script(src: "${rootURL}/plugin/ptai-jenkins-plugin/js/charts.js")

            st.bind(var: "action", value: my)
            script """
                var ${my.urlName}Action = action;
    
                // Map vulnerability level to its localized title
                var levelAttrs = {
                    ${BaseIssue.Level.HIGH.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_high()}'
                    },
                    ${BaseIssue.Level.MEDIUM.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_medium()}'
                    },
                    ${BaseIssue.Level.LOW.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_low()}' 
                    },
                    ${BaseIssue.Level.POTENTIAL.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_potential()}' 
                    },
                    ${BaseIssue.Level.NONE.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_severity_none()}' 
                    }
                };
    
                // Map vulnerability class to its localized title
                var classAttrs = {
                    ${BaseIssue.Type.BLACKBOX.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_clazz_blackbox()}'
                    },
                    ${BaseIssue.Type.CONFIGURATION.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_clazz_configuration()}'
                    },
                    ${BaseIssue.Type.SCA.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_clazz_sca()}'
                    },
                    ${BaseIssue.Type.UNKNOWN.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_clazz_unknown()}'
                    },
                    ${BaseIssue.Type.VULNERABILITY.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_clazz_vulnerability()}'
                    },
                    ${BaseIssue.Type.WEAKNESS.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_clazz_weakness()}'
                    },
                    ${BaseIssue.Type.YARAMATCH.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_clazz_yaramatch()}'
                    }
                };
    
                // Map vulnerability class to its localized title
                var approvalStateAttrs = {
                    ${BaseIssue.ApprovalState.NONE.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_approval_none()}'
                    },
                    ${BaseIssue.ApprovalState.APPROVAL.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_approval_confirmed()}'
                    },
                    ${BaseIssue.ApprovalState.AUTO_APPROVAL.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_approval_auto()}'
                    },
                    ${BaseIssue.ApprovalState.DISCARD.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_approval_rejected()}'
                    },
                    ${BaseIssue.ApprovalState.NOT_EXIST.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_approval_missing()}'
                    }
                };
    
                // Map vulnerability suspected state to its localized title
                var suspectedStateAttrs = {
                    ${true.toString()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_suspected_true()}'
                    },
                    ${false.toString()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_suspected_false()}'
                    }
                };
    
                // Map scan mode to its localized title
                var scanModeAttrs = {
                    ${VulnerabilityIssue.ScanMode.NONE.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_scanmode_none()}'
                    },
                    ${VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_scanmode_entrypoint()}'
                    },
                    ${VulnerabilityIssue.ScanMode.FROM_OTHER.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_scanmode_other()}'
                    },
                    ${VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED.name()}: {
                        title: '${Resources.i18n_misc_enums_vulnerability_scanmode_publicprotected()}'
                    }
                };
    
                const barHeight = 25;
                const bottomMargin = 20;
                const axisLabelMargin = 8;
                const axisFontFamily = 'verdana';
                const axisFontSize = '12px';
                const smallChartHeight = 200;
                // const style = "width: 95%; margin: 0 auto; min-width: 200px; box-shadow: 2px 2px 1px grey; "
                const style = "min-width: 200px; background-color: #f8f8f8f8; "

                ${my.urlName}Action.getVulnerabilityTypeDistribution(function (response) {
                    var option = response.responseJSON;
                    var dataSet = [];
                    option.tooltip = { trigger: 'axis', axisPointer: { type: 'shadow' } };
                    option.xAxis[0].type = 'value';
                    option.xAxis[0].minInterval = 1;
                    option.yAxis[0].type = 'category';
                    option.series[0].type = 'bar';
                    option.series[0].name = '${_("result.misc.quantity.title")}';
                    // TODO: Use level chart label widths also
                    var maxTypeWidth = maxTextWidth(option.yAxis[0].data, axisFontSize + " " + axisFontFamily) + axisLabelMargin;
                    option.grid = { left: maxTypeWidth + "px", top: "0px", bottom: bottomMargin + "px" };
                    var innerHeight = 
                        option.yAxis[0].data.length * barHeight + 
                        bottomMargin; 
                    var chartDivId = "${my.urlName}-type-chart";
                    setupDivFrame(innerHeight, chartDivId, 'width: 100%; ' + style);                  
                    renderChart(chartDivId, option);
                     
                    ${my.urlName}Action.getVulnerabilityLevelDistribution(function (response) {
                        var option = response.responseJSON;
                        option.tooltip = { trigger: 'axis', axisPointer: { type: 'shadow' } };
                        option.xAxis[0].type = 'value';
                        option.xAxis[0].minInterval = 1;
                        option.yAxis[0].type = 'category';
                        option.yAxis[0].inverse = false;
                        // replace vulnerability level title values with localized captions
                        option.yAxis[0].data.forEach(function (item, index) {
                            option.yAxis[0].data[index] = levelAttrs[item].title
                        }, option.yAxis[0].data);

                        option.series[0].type = 'bar';
                        option.series[0].name = '${_("result.misc.quantity.title")}';
                        option.grid = { left: maxTypeWidth + "px", top: "0px", bottom: bottomMargin + "px" };
                        var innerHeight = option.yAxis[0].data.length * barHeight + bottomMargin;
                        var chartDivId = "${my.urlName}-level-chart";
                        setupDivFrame(innerHeight, chartDivId, 'width: 100%; ' + style);                  
                        renderChart(chartDivId, option);
                    });  
                    
                    ${my.urlName}Action.getVulnerabilityClassPie(function (response) {
                        var option = response.responseJSON;
                        option.tooltip = { trigger: 'item' };
                        option.series[0].itemStyle = {
                            borderRadius: 3,
                            borderColor: '#fff',
                            borderWidth: 2
                        };
                        option.series[0].type = 'pie';
                        option.series[0].radius = ['35%', '70%'];
                        
                        option.series[0].label = {
                            normal: {
                                formatter: '{c}',
                                position: 'outside'
                            }, 
                            show: true
                        };
                        option.series[0].avoidLabelOverlap = true;
                        
                        option.series[0].data.forEach(function (item, index) {
                            option.series[0].data[index].name = classAttrs[item.name].title
                        }, option.series[0].data);
                        option.legend = {
                            orient: 'vertical',
                            left: 'left',
                        };
                        var innerHeight = smallChartHeight;
                        var chartDivId = "${my.urlName}-class-pie-chart";
                        setupDivFrame(innerHeight, chartDivId, "margin-right: 16px; " + style);                  
                        renderChart(chartDivId, option);
                    });  
                    
                    ${my.urlName}Action.getVulnerabilityApprovalStatePie(function (response) {
                        var option = response.responseJSON;
                        option.tooltip = { trigger: 'item' };
                        option.series[0].itemStyle = {
                            borderRadius: 3,
                            borderColor: '#fff',
                            borderWidth: 2
                        };
                        option.series[0].type = 'pie';
                        option.series[0].radius = ['35%', '70%'];
                        option.series[0].label = {
                            normal: {
                                formatter: '{c}',
                                position: 'outside'
                            }, 
                            show: true
                        };
                        option.series[0].data.forEach(function (item, index) {
                            option.series[0].data[index].name = approvalStateAttrs[item.name].title
                        }, option.series[0].data);
                        // option.series[0].label = { rotate: 'radial' };
                        option.legend = {
                            orient: 'vertical',
                            left: 'left',
                        };
                        var innerHeight = smallChartHeight;
                        var chartDivId = "${my.urlName}-approval-state-pie-chart";
                        setupDivFrame(innerHeight, chartDivId, style);                  
                        renderChart(chartDivId, option);
                    });  
                    
                    ${my.urlName}Action.getVulnerabilitySuspectedPie(function (response) {
                        var option = response.responseJSON;
                        option.tooltip = { trigger: 'item' };
                        option.series[0].itemStyle = {
                            borderRadius: 3,
                            borderColor: '#fff',
                            borderWidth: 2
                        };
                        option.series[0].type = 'pie';
                        option.series[0].radius = ['35%', '70%'];
                        option.series[0].label = {
                            normal: {
                                formatter: '{c}',
                                position: 'outside'
                            }, 
                            show: true
                        };
                        option.series[0].data.forEach(function (item, index) {
                            option.series[0].data[index].name = suspectedStateAttrs[item.name].title
                        }, option.series[0].data);
                        // option.series[0].label = { rotate: 'radial' };
                        option.legend = {
                            orient: 'vertical',
                            left: 'left',
                        };
                        var innerHeight = smallChartHeight;
                        var chartDivId = "${my.urlName}-suspected-state-pie-chart";
                        setupDivFrame(innerHeight, chartDivId, "margin-right: 16px; " + style);                 
                        renderChart(chartDivId, option);
                    });  

                    ${my.urlName}Action.getVulnerabilityScanModePie(function (response) {
                        var option = response.responseJSON;
                        option.tooltip = { trigger: 'item' };
                        option.series[0].itemStyle = {
                            borderRadius: 3,
                            borderColor: '#fff',
                            borderWidth: 2
                        };
                        option.series[0].type = 'pie';
                        option.series[0].radius = ['35%', '70%'];
                        option.series[0].label = {
                            normal: {
                                formatter: '{c}',
                                position: 'outside'
                            }, 
                            show: true
                        };
                        option.series[0].data.forEach(function (item, index) {
                            option.series[0].data[index].name = scanModeAttrs[item.name].title
                        }, option.series[0].data);
                        // option.series[0].label = { rotate: 'radial' };
                        option.legend = {
                            orient: 'vertical',
                            left: 'left',
                        };
                        var innerHeight = smallChartHeight;
                        var chartDivId = "${my.urlName}-scan-mode-pie-chart";
                        setupDivFrame(innerHeight, chartDivId, style);                  
                        renderChart(chartDivId, option);
                    });
                });
            """
        } else {

        }
    }
}
