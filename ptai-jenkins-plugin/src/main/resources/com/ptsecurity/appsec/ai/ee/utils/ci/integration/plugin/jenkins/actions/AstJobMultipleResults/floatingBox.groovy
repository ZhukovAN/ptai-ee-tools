package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.AstJobMultipleResults

import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper
import lib.FormTagLib
import lib.LayoutTagLib

f = namespace(FormTagLib)
l = namespace(LayoutTagLib)
t = namespace('/lib/hudson')
st = namespace('jelly:stapler')

def latestResults = from.getLatestAstResults(10)

if (null == latestResults || latestResults.isEmpty()) return;

div(class: 'test-trend-caption') {
    text(from.chartCaption)
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
    var ${from.urlName}Action = action;
    ${from.urlName}Action.getVulnerabilityLevelDistributionChart(10, function (response) {
        // Map vulnerability level to its localized title, absolute value and color
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
            item.areaStyle = {  };
            item.emphasis = { focus: 'series' };
        });
        // replace vulnerability level title values with localized captions
        option.series.forEach(function (item) {
            item.name = levelAttrs[item.name].title;
            item.smooth = false;
        });
         
        option.legend.data.forEach(function (item, index) {
            option.legend.data[index] = levelAttrs[item].title
        }, option.legend.data);
         
        renderChart('${from.urlName}-history-chart', option)
    });
"""
