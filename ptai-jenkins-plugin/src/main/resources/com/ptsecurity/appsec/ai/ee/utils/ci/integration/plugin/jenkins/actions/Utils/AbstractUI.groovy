package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.Utils

abstract class AbstractUI {
    def charts = []
    def chartsMap = [:]

    AbstractUI(String prefix) {
        addCharts(prefix)
        for (Chart chart : charts)
            chartsMap[chart.type] = chart
    }

    abstract addCharts(String prefix);
}
