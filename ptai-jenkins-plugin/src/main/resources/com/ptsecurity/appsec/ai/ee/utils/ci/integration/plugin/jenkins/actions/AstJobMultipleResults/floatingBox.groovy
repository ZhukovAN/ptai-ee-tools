package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobMultipleResults

import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts.BaseJsonChartDataModel
import lib.FormTagLib
import lib.LayoutTagLib

f = namespace(FormTagLib)
l = namespace(LayoutTagLib)
t = namespace('/lib/hudson')
st = namespace('jelly:stapler')

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
    ${from.urlName}Action.getVulnerabilityLevelDistributionChart(10, function (response) {
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

        var option = response.responseJSON;

        option.title = { show: false };

        option.legend.top = 'bottom';
        option.legend.left = 'center';

        option.tooltip = {
            trigger: 'axis',
            axisPointer: {
                type: 'cross',
                label: {
                    backgroundColor: '#6a7985'
                }
            }
        };

        option.grid = { bottom: 25, top: 10, left: 20, right: 10, containLabel: true }; 

        option.xAxis[0].type = 'category'
        option.xAxis[0].boundaryGap = false
        option.xAxis[0].data.forEach(function (item, index) {
            this[index] = '#' + item;
        }, option.xAxis[0].data);

        option.yAxis[0].type = 'value'
        option.yAxis[0].minInterval = 1

        option.series.forEach(function (item) {
            item.type = 'line';
            item.stack = '0';
            item.itemStyle = { color: levelAttrs[item.name].itemColor };
            item.areaStyle = {  };
            item.emphasis = { focus: 'series' };
        });
        // replace vulnerability level title values with localized captions
        option.series.forEach(function (item) {
            item.name = levelAttrs[item.name].title
        });
         
        option.legend.data.forEach(function (item, index) {
            option.legend.data[index] = levelAttrs[item].title
        }, option.legend.data);
         
        renderChart('${from.urlName}-history-chart', option)
    });
"""
