package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.actions.Utils

class Chart {
    enum Type {
        ISSUE_LEVELS_BAR,
        ISSUE_CLASS_PIE, APPROVAL_STATUS_PIE,
        SUSPECTED_STATE_PIE, SCAN_MODE_PIE,
        ISSUE_TYPE_BAR,
        VULNERABILITY_TYPE_BAR,

        LEVELS_HISTORY_BAR, APPROVAL_HISTORY_BAR,
        ISSUE_TYPE_HISTORY_BAR,
        SCAN_DURATION_HISTORY_BAR
    }
    Type type

    String divId, noDataDivId
    int col, row, width
    String name, title

    Chart(Type type, int col, int row, int width, String prefix, String name, String title) {
        this.type = type
        this.divId = "${prefix}-${name}"
        this.noDataDivId = "${prefix}-${name}-no-data"
        this.col = col
        this.row = row
        this.width = width
        this.name = name
        this.title = title
    }
}


