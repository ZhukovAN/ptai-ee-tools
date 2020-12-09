package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BaseReportTest {
    @Test
    @DisplayName("Convert enums from strings and vice versa")
    void testEnumConversion() {
        Reports.Report item = new Reports.Report();
        item.setFormat( Reports.Report.Format.valueOf(Reports.Locale.EN.name()));
    }
}