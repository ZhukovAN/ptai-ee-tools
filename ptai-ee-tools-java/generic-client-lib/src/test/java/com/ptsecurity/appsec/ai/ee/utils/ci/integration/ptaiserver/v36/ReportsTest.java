package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Data.Format.JSON;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Data.Format.XML;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Locale.RU;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Report.Format.HTML;

class ReportsTest {
    @SneakyThrows
    @Test
    @DisplayName("Test JSON-defined report settings representation")
    public void testReportsJsonDefinition() {
        Reports reports = new Reports();
        Reports.RawData raw = new Reports.RawData();
        raw.setFileName("raw.json");
        reports.getRaw().add(raw);

        Reports.Data data = new Reports.Data();
        data.setFormat(JSON);
        data.setFileName("data.en.json");
        data.setLocale(Reports.Locale.EN);
        reports.getData().add(data);

        data.setFormat(XML);
        data.setFileName("data.en.xml");
        reports.getData().add(data);

        Reports.Report report = new Reports.Report();
        report.setFormat(HTML);
        report.setTemplate("Отчет PCI DSS 3.2");
        report.setLocale(RU);
        report.setFileName("report.ru.xml");
        reports.getReport().add(report);

        report.setTemplate("Отчет PCI DSS");
        report.setFileName("report.ru.xml");
        reports.getReport().add(report);

        report.setTemplate("OWASP");
        report.setFileName("report.ru.xml");
        reports.getReport().add(report);

        reports.fix();

        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(reports));
    }

    @Test
    @DisplayName("Convert string values to enums")
    void convertEnums() {
        Assertions.assertEquals(HTML, Reports.Report.Format.from("Html"));
        Assertions.assertEquals(RU, Reports.Locale.from("ru-RU"));
    }
}