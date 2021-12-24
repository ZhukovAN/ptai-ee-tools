package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.TRUE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

public class ReportsHelper {
    public static Reports convert(@NonNull final Map<String, String> data) throws GenericException {
        Reports res = new Reports();
        if (TRUE.equals(data.getOrDefault(REPORTING_REPORT, Defaults.REPORTING_REPORT))) {
            Reports.Report report = new Reports.Report();
            report.setFormat(Reports.Report.Format.valueOf(
                    data.getOrDefault(REPORTING_REPORT_FORMAT, Defaults.REPORTING_REPORT_FORMAT)));
            report.setLocale(Reports.Locale.from(
                    data.getOrDefault(REPORTING_REPORT_LOCALE, Defaults.REPORTING_REPORT_LOCALE)));
            report.setFileName(data.get(REPORTING_REPORT_FILE));
            report.setTemplate(data.get(REPORTING_REPORT_TEMPLATE));
            if (StringUtils.isNotEmpty(data.get(REPORTING_REPORT_FILTER)))
                report.setFilters(ReportUtils.validateJsonFilter(data.get(REPORTING_REPORT_FILTER)));
            res.getReport().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_DATA, Defaults.REPORTING_DATA))) {
            Reports.Data report = new Reports.Data();
            report.setFormat(Reports.Data.Format.valueOf(
                    data.getOrDefault(REPORTING_DATA_FORMAT, Defaults.REPORTING_DATA_FORMAT)));
            report.setLocale(Reports.Locale.from(
                    data.getOrDefault(REPORTING_DATA_LOCALE, Defaults.REPORTING_DATA_LOCALE)));
            report.setFileName(data.get(REPORTING_DATA_FILE));
            if (StringUtils.isNotEmpty(data.get(REPORTING_DATA_FILTER)))
                report.setFilters(ReportUtils.validateJsonFilter(data.get(REPORTING_DATA_FILTER)));
            res.getData().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_RAWDATA, Defaults.REPORTING_RAWDATA))) {
            Reports.RawData report = new Reports.RawData();
            report.setFileName(data.get(REPORTING_RAWDATA_FILE));
            res.getRaw().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_SARIF, Defaults.REPORTING_SARIF))) {
            Reports.Sarif report = new Reports.Sarif();
            report.setFileName(data.get(REPORTING_SARIF_FILE));
            res.getSarif().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_SONARGIIF, Defaults.REPORTING_SONARGIIF))) {
            Reports.SonarGiif report = new Reports.SonarGiif();
            report.setFileName(data.get(REPORTING_SONARGIIF_FILE));
            res.getSonarGiif().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_JSON, Defaults.REPORTING_JSON)))
            res.append(ReportUtils.validateJsonReports(data.get(REPORTING_JSON_SETTINGS)));

        return res;
    }
}
