package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobTableResults

import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import lib.FormTagLib
import lib.LayoutTagLib

def f = namespace(FormTagLib)
def l = namespace(LayoutTagLib)
def st = namespace("jelly:stapler")

script(src: "${rootURL}/plugin/ptai-jenkins-plugin/webjars/echarts/echarts.common.min.js")
script(src: "${rootURL}/plugin/ptai-jenkins-plugin/js/charts.js")

l.layout(title: "PT AI AST report") {
    l.side_panel() {
        st.include(page: "sidepanel.jelly", it: my.project)
    }
    l.main_panel() {
        h1(_("statistics.label"))
        h2(_("statistics.breakdown.label"))
        table(style: "width: 95%; margin: 0 auto; min-width: 200px; border-collapse: collapse; ") {
            colgroup() {
                col(width: "50%")
                col(width: "50%")
            }
            tbody() {
                tr() {
                    td(style: "margin-left: 0px; margin-right: 0px; padding-right: 0px; padding-left: 0px; ", colspan: "2") {
                        h3(_("result.breakdown.level.title"))
                    }
                }
                tr() {
                    td(style: "padding-right: 8px; padding-left: 0px; ") {
                        h3(_("statistics.by.level.label"))
                        div(
                                id: "${my.urlName}-level-history-chart",
                                class: 'graph-cursor-pointer') {}
                    }
                    td(style: "padding-left: 8px; padding-right: 0px; ") {
                        h3(_("statistics.by.approval.label"))
                        div(
                                id: "${my.urlName}-approval-history-chart",
                                class: 'graph-cursor-pointer') {}
                    }
                }
                tr() {
                    td(style: "padding-right: 8px; padding-left: 0px; ") {
                        h3(_("statistics.by.type.label"))
                        div(
                                id: "${my.urlName}-type-history-chart",
                                class: 'graph-cursor-pointer') {}
                    }
                }
                tr() {
                    td(style: "padding-right: 8px; padding-left: 0px; ") {
                        h3("${Resources.i18n_ast_result_statistics_duration()}")
                        div(
                                id: "${my.urlName}-scan-duration-history-chart",
                                class: 'graph-cursor-pointer') {}
                    }
                }
            }
        }

        def historyLength = 10;

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
            
            createBuildHistoryChart(
                "${my.urlName}-level-history-chart", 
                ${my.getLevelHistoryChart(historyLength)}, levelAttrs);
            
            createBuildHistoryChart(
                "${my.urlName}-approval-history-chart", 
                ${my.getApprovalHistoryChart(historyLength)}, approvalStateAttrs);
            
            createBuildHistoryChart(
                "${my.urlName}-type-history-chart", 
                ${my.getTypeHistoryChart(historyLength)}, typeAttrs);

            var option = ${my.getScanDurationHistoryChart(historyLength)};
            option.legend.data[0] = "${Resources.i18n_ast_result_statistics_duration_sec()}"
            option.series[0].name = "${Resources.i18n_ast_result_statistics_duration_sec()}"
            createDurationHistoryChart(
                "${my.urlName}-scan-duration-history-chart", 
                option);
        """
    }
}
