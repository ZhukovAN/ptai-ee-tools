package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Project;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.ReportFormatType;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.ReportTemplateModel;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.BaseIT;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Data.Format.JSON;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Data.Format.XML;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Report.Format.HTML;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("Reports generation integration tests")
@Tag("integration")
public class ReportsIT extends BaseIT {
    @SneakyThrows
    @Test
    @DisplayName("List report templates for every locale available")
    public void testReportTemplatesList() {
        Utils utils = createUtils();
        for (Reports.Locale locale : Reports.Locale.values()) {
            List<ReportTemplateModel> templates = utils.getReportTemplates(locale);
            Assertions.assertFalse(templates.isEmpty(), "Report templates list empty for locale " + locale.getValue());
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Search for missing report template")
    public void testSearchForMissingReportTemplate() {
        Utils utils = createUtils();

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
        report.setLocale(Reports.Locale.RU);
        report.setFileName("report.ru.xml");
        reports.getReport().add(report);

        report.setTemplate("Отчет PCI DSS");
        report.setFileName("report.ru.xml");
        reports.getReport().add(report);

        report.setTemplate("OWASP");
        report.setFileName("report.ru.xml");
        reports.getReport().add(report);

        ApiException e = assertThrows(ApiException.class, () -> reports.validate().check(utils));
        utils.severe(e);
    }

    @DisplayName("Test HTML / JSON report generation for randomly chosen scan results with randomly chosen report template")
    @SneakyThrows
    @Test
    public void testReportGeneration() {
        ScanResult scanResult = getRandomScanResult();
        String projectName = projectsApi.apiProjectsProjectIdGet(scanResult.getProjectId()).getName();
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project project = createProject(projectName);

        final Reports.Locale locale = Reports.Locale.EN;
        List<ReportTemplateModel> templates = project.getReportTemplates(locale);
        ReportTemplateModel template = templates.get(new Random().nextInt(templates.size()));

        project.generateReport(scanResult.getProjectId(), scanResult.getId(), template.getName(), locale, ReportFormatType.HTML, null);
        project.generateReport(scanResult.getProjectId(), scanResult.getId(), template.getName(), locale, ReportFormatType.JSON, null);
    }
}
