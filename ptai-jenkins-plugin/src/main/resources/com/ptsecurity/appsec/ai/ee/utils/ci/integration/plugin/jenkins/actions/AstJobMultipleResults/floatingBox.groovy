package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobMultipleResults


import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources

st = namespace('jelly:stapler')

def latestResults = from.getLatestAstResults(10)
if (null == latestResults || latestResults.isEmpty()) return

div(class: 'test-trend-caption') {
    text(Resources.i18n_ast_result_charts_trend_label())
}

// Fix for pipeline jobs, see https://issues.jenkins.io/browse/JENKINS-41753?jql=project%20%3D%20JENKINS%20AND%20component%20%3D%20pipeline-stage-view-plugin
div(
        id: "${from.urlName}-history-chart",
        class: 'graph-cursor-pointer',
        style: "width: 500px; min-height: 200px; min-width: 500px; height: 200px; z-index:1;") {}

script(src: "${rootURL}/plugin/ptai-jenkins-plugin/webjars/echarts/echarts.common.min.js")
script(src: "${rootURL}/plugin/ptai-jenkins-plugin/js/charts.js")

st.bind(var: "action", value: from)

script """
    action.getVulnerabilityLevelTrendChart(10, function (response) {
        createTrendChart('${from.urlName}-history-chart', response.responseJSON)
    });
"""