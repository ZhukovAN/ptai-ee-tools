package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobSingleResult

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief
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
import org.apache.commons.lang.StringUtils
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

def widthOffset = 100
def smallChartHeight = 200
def smallChartMinWidth = 450
def smallChartGap = 16
def bigChartMinWidth = smallChartMinWidth * 2 + smallChartGap
def smallChartStyle = "min-width: ${smallChartMinWidth}px; background-color: #f8f8f8f8; "
def bigChartStyle = "min-width: " + bigChartMinWidth + "px; background-color: #f8f8f8f8; "
def bigDivStyle = "width: ${widthOffset}%; margin: 0 auto; min-width: " + bigChartMinWidth + "px; display: grid; grid-template-columns: 50% 50%; "

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

enum ColorType { BORDER, BOLD, BACKGROUND }
neutralColors = [:]
neutralColors[ColorType.BOLD] = new Color(116, 116, 116)
neutralColors[ColorType.BACKGROUND] = Color.decode('#f8f8f8')
neutralColors[ColorType.BORDER] = new Color(230, 230, 230)

Map<ColorType, Color> redColors = [:]
redColors[ColorType.BOLD] = new Color(LEVEL_COLORS.get(BaseIssue.Level.HIGH))
Color tempColor = redColors[ColorType.BOLD]
float[] hsb = new float[3]
Color.RGBtoHSB(tempColor.red, tempColor.green, tempColor.blue, hsb)
hsb[1] = 0.05f
hsb[2] = 1.0f
redColors[ColorType.BACKGROUND] = Color.getHSBColor(hsb[0], hsb[1], hsb[2])
Color.RGBtoHSB(tempColor.red, tempColor.green, tempColor.blue, hsb)
hsb[1] = 0.3f
hsb[2] = 1.0f
redColors[ColorType.BORDER] = Color.getHSBColor(hsb[0], hsb[1], hsb[2])

greenColors = [:]
greenColors[ColorType.BOLD] = new Color(LEVEL_COLORS.get(BaseIssue.Level.LOW))
tempColor = greenColors[ColorType.BOLD]
Color.RGBtoHSB(tempColor.red, tempColor.green, tempColor.blue, hsb)
hsb[1] = 0.05f
hsb[2] = 1.0f
greenColors[ColorType.BACKGROUND] = Color.getHSBColor(hsb[0], hsb[1], hsb[2])
Color.RGBtoHSB(tempColor.red, tempColor.green, tempColor.blue, hsb)
hsb[1] = 0.3f
hsb[2] = 0.9f
greenColors[ColorType.BORDER] = Color.getHSBColor(hsb[0], hsb[1], hsb[2])

def c(Color color) {
    return String.format('#%06x', color.getRGB() & 0xFFFFFF)
}

def divStyle(x, y, w, h) {
    return divStyle(
            x, y,
            w, h,
            neutralColors[ColorType.BORDER],
            neutralColors[ColorType.BOLD],
            neutralColors[ColorType.BACKGROUND])
}

def divStyle(x, y, w, h, Color borderColor) {
    return divStyle(
            x, y,
            w, h,
            borderColor,
            neutralColors[ColorType.BOLD],
            neutralColors[ColorType.BACKGROUND])
}

def divStyle(x, y, w, h, Color borderColor, Color boldLineColor) {
    return divStyle(
            x, y,
            w, h,
            borderColor,
            boldLineColor,
            neutralColors[ColorType.BACKGROUND])
}

def divStyle(x, y, w, h, Color borderColor, Color boldLineColor, Color backgroundColor) {
    def style = "background-color: ${c(backgroundColor)}; "

    if (0 == x) {
        style += 'border-left-width: 4px; border-left-style: solid; '
        style += "border-left-color: ${c(boldLineColor)}; "
        style += 'padding-left: 20px; margin-left: 0px; '
    }
    if (w - 1 == x) {
        style += 'border-right-width: 1px; border-right-style: solid; '
        style += "border-right-color: ${c(borderColor)}; "
    }

    if (0 == y) {
        style += 'padding-top: 8px; '
        style += 'border-top-width: 1px; border-top-style: solid; '
        style += "border-top-color: ${c(borderColor)}; "
    }
    if (h - 1 == y) {
        style += 'padding-bottom: 8px; '
        style += 'border-bottom-width: 1px; border-bottom-style: solid; '
        style += "border-bottom-color: ${c(borderColor)}; "
    }

    return style
}

styleTableFirstColumn = 'padding-top: 0px; padding-bottom: 0px; padding-right: 0px; padding-left: 0px; '
styleTableSecondColumn = styleTableFirstColumn + 'font-weight:bold; '
styleTable = "width: ${widthOffset}%; margin: 0 auto; min-width: ${bigChartMinWidth}px; border-collapse: collapse; margin-top: 10px; "

def showTable(data, Color borderColor, Color boldLineColor, Color backgroundColor) {
    table(style: "${styleTable}") {
        colgroup() {
            col(width: "300px")
        }
        tbody() {
            data.eachWithIndex{key, value, i ->
                tr() {
                    td(align: "left", style: "${styleTableFirstColumn}") {
                        div(style: "${divStyle(0, i, 2, data.size(), borderColor, boldLineColor, backgroundColor)}") {
                            text(key)
                        }
                    }
                    td(align: "left", style: "${styleTableSecondColumn}") {
                        div(style: "${divStyle(1, i, 2, data.size(), borderColor, boldLineColor, backgroundColor)}") {
                            text(value)
                        }
                    }
                }
            }
        }
    }
}

def showTable(data) {
    showTable(data, neutralColors[ColorType.BORDER], neutralColors[ColorType.BOLD], neutralColors[ColorType.BACKGROUND])
}

l.layout(title: "PT AI AST report") {
    l.side_panel() {
        st.include(page: "sidepanel.jelly", from: my.run, it: my.run, optional: true)
    }

    l.main_panel() {
        def scanBriefDetailed = my.getScanBriefDetailed()

        h1(_("result.title"))
        h2(_("scan.settings.title"))
        def scanSettings = [:]
        scanSettings[_("scan.settings.project")] = "${scanBriefDetailed.projectName}"
        scanSettings[_("scan.settings.url")] = "${scanBriefDetailed.scanSettings.url}"
        scanSettings["${Resources.i18n_ast_settings_base_programminglanguage_label()}"] = "${scanBriefDetailed.scanSettings.language}"
        scanSettings["${Resources.i18n_ast_settings_mode_label()}"] = scanBriefDetailed.getUseAsyncScan()
                ? Resources.i18n_ast_settings_mode_asynchronous_label()
                : Resources.i18n_ast_settings_mode_synchronous_label()
        showTable(scanSettings)

        if (null != scanBriefDetailed.statistics) {
            def statistics = [:]
            ZonedDateTime scanDate = ZonedDateTime.parse(scanBriefDetailed.statistics.scanDateIso8601)
            scanDate = scanDate.withZoneSameInstant(ZoneId.systemDefault())
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yy HH:mm:ss")
            statistics[_("scan.timestamp")] = "${scanDate.format(formatter)}"
            durationMs = Duration.parse(scanBriefDetailed.statistics.scanDurationIso8601).toMillis()
            statistics[_("scan.duration")] = "${DurationFormatUtils.formatDuration(durationMs, "H:mm:ss", true)}"
            showTable(statistics)
        }

        if (!scanBriefDetailed.getUseAsyncScan()) {
            def state = [:]
            def borderColor = neutralColors[ColorType.BORDER]
            def boldLineColor = neutralColors[ColorType.BOLD]
            def backgroundColor = neutralColors[ColorType.BACKGROUND]
            if (scanBriefDetailed.getState() in [ScanBrief.State.ABORTED, ScanBrief.State.FAILED]) {
                borderColor = redColors[ColorType.BORDER]
                boldLineColor = redColors[ColorType.BOLD]
                backgroundColor = redColors[ColorType.BACKGROUND]
                state["${Resources.i18n_ast_result_status_label()}"] = ScanBrief.State.ABORTED == scanBriefDetailed.getState()
                        ? Resources.i18n_ast_result_status_interrupted_label()
                        : Resources.i18n_ast_result_status_failed_label()
            } else
                state["${Resources.i18n_ast_result_status_label()}"] = Resources.i18n_ast_result_status_success_label()
            showTable(state, borderColor, boldLineColor, backgroundColor)

            def policy = [:]
            borderColor = neutralColors[ColorType.BORDER]
            boldLineColor = neutralColors[ColorType.BOLD]
            backgroundColor = neutralColors[ColorType.BACKGROUND]
            if (Policy.State.REJECTED == scanBriefDetailed.getPolicyState()) {
                borderColor = redColors[ColorType.BORDER]
                boldLineColor = redColors[ColorType.BOLD]
                backgroundColor = redColors[ColorType.BACKGROUND]
                policy["${Resources.i18n_ast_result_policy_label()}"] = Resources.i18n_ast_result_policy_failed_label()
            } else if (Policy.State.CONFIRMED == scanBriefDetailed.getPolicyState()) {
                borderColor = greenColors[ColorType.BORDER]
                boldLineColor = greenColors[ColorType.BOLD]
                backgroundColor = greenColors[ColorType.BACKGROUND]
                policy["${Resources.i18n_ast_result_policy_label()}"] = Resources.i18n_ast_result_policy_confirmed_label()
            } else
                policy["${Resources.i18n_ast_result_policy_label()}"] = Resources.i18n_ast_result_policy_none_label()
            showTable(policy, borderColor, boldLineColor, backgroundColor)
        }

        def versions = [:]
        if (StringUtils.isNotEmpty(scanBriefDetailed.ptaiServerUrl))
            versions[Resources.i18n_ast_settings_server_url_label()] = scanBriefDetailed.ptaiServerUrl
        versions[_("environment.server.version")] = scanBriefDetailed.ptaiServerVersion
        versions[_("environment.agent.version")] = scanBriefDetailed.ptaiAgentVersion
        showTable(versions)

        if (!my.isEmpty()) {
            h2(_("result.breakdown.title"))

            div(style: "${bigDivStyle}") {
                div(style: "grid-area: 1 / 1 / 2 / 3; ") {
                    h3(_("result.breakdown.level.title"))
                    div(
                            id: "${my.urlName}-level-chart",
                            class: 'graph-cursor-pointer') {
                    }
                    div(id : "${my.urlName}-level-chart-no-data") {
                        text("${Resources.i18n_ast_result_charts_message_nodata_label().toUpperCase()}")
                    }
                }
                div(style: "grid-area: 2 / 1 / 3 / 2; padding-right: 8px; ") {
                    h3(_("result.breakdown.class.title"))
                    div(
                            id: "${my.urlName}-type-pie-chart",
                            class: 'graph-cursor-pointer; ') {}
                }
                div(style: "grid-area: 2 / 2 / 3 / 3; padding-left: 8px; ") {
                    h3(_("result.breakdown.approvalstate.title"))
                    div(
                            id: "${my.urlName}-approval-state-pie-chart",
                            class: 'graph-cursor-pointer; ') {}
                }
                div(style: "grid-area: 3 / 1 / 4 / 2; padding-right: 8px; ") {
                    h3(_("result.breakdown.suspected.title"))
                    div(
                            id: "${my.urlName}-suspected-state-pie-chart",
                            class: 'graph-cursor-pointer; ') {}
                }
                div(style: "grid-area: 3 / 2 / 4 / 3; padding-left: 8px; ") {
                    h3(_("result.breakdown.scanmode.title"))
                    div(
                            id: "${my.urlName}-scan-mode-pie-chart",
                            class: 'graph-cursor-pointer; ') {}
                }
                div(style: "grid-area: 4 / 1 / 5 / 3; ") {
                    h3(id: "h3", _("result.breakdown.type.title"))
                    div(
                            id: "${my.urlName}-type-chart",
                            class: 'graph-cursor-pointer') {
                    }
                    div(id : "${my.urlName}-type-chart-no-data") {
                        text("${Resources.i18n_ast_result_charts_message_nodata_label().toUpperCase()}")
                    }
                }
            }

            st.bind(var: "action", value: my)
            script """
                var fontSize = \$("h3").getStyle('fontSize');
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
                \$("${my.urlName}-type-chart-no-data").setStyle(messageNoDataStyle);
                \$("${my.urlName}-level-chart-no-data").setStyle(messageNoDataStyle);

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
                var typeAttrs = {
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
                
                var option = ${my.getVulnerabilityTypeDistribution()};
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
                
                if (0 === option.series[0].data.length) {
                    \$(chartDivId).hide();
                    setupDivFrame(36, chartDivId + "-no-data", false);
                } else {
                    \$(chartDivId + "-no-data").hide();
                    setupDivFrame(innerHeight, chartDivId, false);                  
                    renderChart(chartDivId, option);
                }
                
                var option = ${my.getVulnerabilityLevelDistribution()};
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
                chartDivId = "${my.urlName}-level-chart";
                if (0 === option.series[0].data.length) {
                    \$(chartDivId).hide();
                    setupDivFrame(36, chartDivId + "-no-data", false);
                } else {
                    \$(chartDivId + "-no-data").hide();
                    setupDivFrame(innerHeight, chartDivId, false);                  
                    renderChart(chartDivId, option);
                }
                     
                createDistributionPieChart(
                    "${my.urlName}-type-pie-chart",
                    ${my.getVulnerabilityTypePie()}, typeAttrs);

                createDistributionPieChart(
                    "${my.urlName}-approval-state-pie-chart", 
                    ${my.getVulnerabilityApprovalStatePie()}, approvalStateAttrs);
                
                createDistributionPieChart(
                    "${my.urlName}-suspected-state-pie-chart", 
                    ${my.getVulnerabilitySuspectedPie()}, suspectedStateAttrs);

                createDistributionPieChart(
                    "${my.urlName}-scan-mode-pie-chart", 
                    ${my.getVulnerabilityScanModePie()}, scanModeAttrs);
            """
        }
    }
}
