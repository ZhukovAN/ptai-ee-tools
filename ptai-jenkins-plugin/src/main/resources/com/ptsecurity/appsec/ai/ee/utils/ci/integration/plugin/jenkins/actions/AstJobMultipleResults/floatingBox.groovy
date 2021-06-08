package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobMultipleResults

f = namespace(lib.FormTagLib)
l = namespace(lib.LayoutTagLib)
t = namespace('/lib/hudson')
st = namespace('jelly:stapler')

if (from.resultsAvailable()) {
    div(class: 'test-trend-caption') {
        text(from.chartCaption)
    }

    div(
            id: "${from.urlName}-history-chart",
            class: 'graph-cursor-pointer',
            style: "width: 500px; min-height: 200px; min-width: 500px; height: 200px;") {}

    script(src: "${rootURL}/plugin/ptai-jenkins-plugin/webjars/echarts/echarts.common.min.js")
    script(src: "${rootURL}/plugin/ptai-jenkins-plugin/js/charts.js")

    st.bind(var:"action", value:from)
    script """
        var ${from.urlName}Action = action;
        ${from.urlName}Action.getSeverityDistributionTrend(function (data) {
            renderTrendChart("${from.urlName}-history-chart", data.responseJSON)
        });
    """
}