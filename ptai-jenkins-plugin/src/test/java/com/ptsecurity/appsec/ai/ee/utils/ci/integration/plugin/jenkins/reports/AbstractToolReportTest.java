package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.reports;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AbstractToolReportTest {
    @Test
    @DisplayName("Convert enums from strings")
    void convertEnums() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            new Reports.Report().setFormat(Reports.Report.Format.valueOf(Reports.Locale.EN.name()));
        });
    }
}