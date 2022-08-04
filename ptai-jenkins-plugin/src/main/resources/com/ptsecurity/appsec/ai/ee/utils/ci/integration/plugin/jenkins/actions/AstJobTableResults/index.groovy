package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobTableResults

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib
import lib.LayoutTagLib

def f = namespace(FormTagLib)
def l = namespace(LayoutTagLib)
def st = namespace("jelly:stapler")

def widthOffset = 100;
def smallChartHeight = 200;
def smallChartMinWidth = 450;
def smallChartGap = 16;
def bigChartMinWidth = smallChartMinWidth * 2 + smallChartGap;
def smallChartStyle = "min-width: ${smallChartMinWidth}px; background-color: #f8f8f8f8; ";
def bigChartStyle = "min-width: " + bigChartMinWidth + "px; background-color: #f8f8f8f8; ";
def bigDivStyle = "width: ${widthOffset}%; margin: 0 auto; min-width: " + bigChartMinWidth + "px; display: grid; grid-template-columns: 50% 50%; ";
def tableStyle = "width: ${widthOffset}%; margin: 0 auto; min-width: ${bigChartMinWidth}px; border-collapse: collapse; margin-top: 10px; "

def historyLength = 10;

// Make groovy values available for JavaScript
script """
    const smallChartHeight = ${smallChartHeight};
    const smallChartMinWidth = ${smallChartMinWidth};
    const smallChartGap = ${smallChartGap};
    const bigChartMinWidth = ${bigChartMinWidth};
    const smallChartStyle = '${smallChartStyle}';
    const bigChartStyle = '${bigChartStyle}';
"""

script(src: "${rootURL}/plugin/ptai-jenkins-plugin/webjars/echarts/echarts.min.js")
script(src: "${rootURL}/plugin/ptai-jenkins-plugin/js/charts.js")

l.layout(title: "PT AI AST report") {
    l.side_panel() {
        st.include(page: "sidepanel.jelly", it: my.project)
    }
    l.main_panel() {
        h1(_("statistics.label"))
        h2(id: "h2", _("statistics.breakdown.label"))
        def latestResults = my.getLatestAstResults(historyLength)
        if (null == latestResults || latestResults.isEmpty()) {
            div(id : "${my.urlName}-no-data") {
                text("${Resources.i18n_ast_result_charts_message_noscans_label().toUpperCase()}")
            }
            script """
                var fontSize = \$("h2").getStyle('fontSize');
                var messageNoDataStyle = {  
                    'fontSize' : fontSize,
                    'fontWeight' : 'bold',
                    'fontStyle' : 'italic',
                    'color' : 'lightgray',
                    'textAlign' : 'center',
                    'display' : 'flex',
                    'justifyContent' : 'center',
                    'alignItems' : 'center'
                };
                \$("${my.urlName}-no-data").setStyle(messageNoDataStyle);
                setupDivFrame(36, "${my.urlName}-no-data", false);
            """
        } else {
            // text(BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(my.getScanStageDurationHistoryChart(historyLength)))
            div(style: "${bigDivStyle}") {
                div(style: "grid-area: 1 / 1 / 2 / 2; padding-right: 8px; ") {
                    h3(_("statistics.by.level.label"))
                    div(
                            id: "${my.urlName}-level-history-chart",
                            class: 'graph-cursor-pointer') {}
                }
                div(style: "grid-area: 1 / 2 / 2 / 3; padding-left: 8px; ") {
                    h3(_("statistics.by.approval.label"))
                    div(
                            id: "${my.urlName}-approval-history-chart",
                            class: 'graph-cursor-pointer') {}
                }
                div(style: "grid-area: 2 / 1 / 3 / 3; ") {
                    td(style: "padding-right: 8px; padding-left: 0px; ") {
                        h3(_("statistics.by.type.label"))
                        div(
                                id: "${my.urlName}-type-history-chart",
                                class: 'graph-cursor-pointer') {}
                    }
                }
                div(style: "grid-area: 3 / 1 / 4 / 3; ") {
                    h3("${Resources.i18n_ast_result_statistics_duration_label()}")
                    div(
                            id: "${my.urlName}-scan-stage-duration-history-chart",
                            class: 'graph-cursor-pointer') {}
                }
            }

            script """
                // Map vulnerability level to its localized title
                var levelAttrs = {
                    TOTAL: {
                        title: '${Resources.i18n_misc_enums_vulnerability_total()}'
                    },
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
                var approvalStateAttrs = {
                    TOTAL: {
                        title: '${Resources.i18n_misc_enums_vulnerability_total()}'
                    },
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
                
                // Map vulnerability class to its localized title
                var typeAttrs = {
                    TOTAL: {
                        title: '${Resources.i18n_misc_enums_vulnerability_total()}'
                    },
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
                var scanStageAttrs = {
                    DURATION: {
                        title: '${Resources.i18n_ast_result_statistics_duration_sec_label()}'
                    },
                    ${Stage.ABORTED.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_aborted()}'
                    },
                    ${Stage.AUTOCHECK.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_autocheck()}'
                    },
                    ${Stage.DONE.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_done()}'
                    },
                    ${Stage.ENQUEUED.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_enqueued()}'
                    },
                    ${Stage.FAILED.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_failed()}'
                    },
                    ${Stage.FINALIZE.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_finalize()}'
                    },
                    ${Stage.INITIALIZE.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_initialize()}'
                    },
                    ${Stage.PRECHECK.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_precheck()}'
                    },
                    ${Stage.SCAN.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_scan()}'
                    },
                    ${Stage.SETUP.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_setup()}'
                    },
                    ${Stage.UNKNOWN.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_unknown()}'
                    },
                    ${Stage.UPLOAD.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_upload()}'
                    },
                    ${Stage.VFSSETUP.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_vfssetup()}'
                    },
                    ${Stage.ZIP.name()}: {
                        title: '${Resources.i18n_misc_enums_progress_stage_zip()}'
                    }
                };
                
                createBuildHistoryChart(
                    "${my.urlName}-level-history-chart", 
                    ${my.getLevelHistoryChart(historyLength)}, levelAttrs);
                
                createBuildHistoryChart(
                    "${my.urlName}-approval-history-chart", 
                    ${my.getApprovalHistoryChart(historyLength)}, approvalStateAttrs);
                
                createBuildHistoryChart(
                    "${my.urlName}-type-history-chart", 
                    ${my.getTypeHistoryChart(historyLength)}, typeAttrs, false);
    
                var option = ${my.getScanStageDurationHistoryChart(historyLength)};
                // option.legend.data[0] = "${Resources.i18n_ast_result_statistics_duration_sec_label()}"
                // option.series[0].name = "${Resources.i18n_ast_result_statistics_duration_sec_label()}"
                createBuildHistoryChart(
                    "${my.urlName}-scan-stage-duration-history-chart", 
                    option, scanStageAttrs, false);
            """
        }
    }
}
