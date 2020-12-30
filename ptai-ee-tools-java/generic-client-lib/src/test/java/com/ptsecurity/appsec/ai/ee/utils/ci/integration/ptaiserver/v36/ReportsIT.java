package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportFormatType;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.ReportTemplateModel;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import lombok.SneakyThrows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Data.Format.JSON;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Data.Format.XML;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Reports.Report.Format.HTML;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ReportsIT extends BaseIT {
    protected static final String EXISTING_PROJECT = "app01";
    protected static final UUID EXISTING_SCAN_RESULT_ID = UUID.fromString("a221c55d-038b-41ed-91e8-5c9d67cb3337");

    @SneakyThrows
    @Test
    @DisplayName("List all the report templates")
    public void testReportTemplatesList() {
        Utils utils = new Utils();
        utils.setUrl(client.getUrl());
        utils.setToken(client.getToken());
        utils.setCaCertsPem(client.getCaCertsPem());
        utils.init();

        for (Reports.Locale locale : Reports.Locale.values()) {
            List<ReportTemplateModel> templates = utils.getReportTemplates(locale);
            for (ReportTemplateModel template : templates)
                System.out.println(String.format("[%s] %s", locale, template.getName()));
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

        reports.fix();

        Exception e = assertThrows(ApiException.class, () -> reports.validate().check(utils));
        utils.severe((ApiException) e);
    }

    @SneakyThrows
    @Test
    public void testReportGeneration() {
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project project = createProject(EXISTING_PROJECT);

        List<ReportTemplateModel> templates = project.getReportTemplates(Reports.Locale.EN);
        int templateIdx = (int) Math.round(Math.random() * templates.size());
        UUID templateId = templates.get(templateIdx).getId();
        UUID projectId = project.searchProject();

        File reportTempFile = project.generateReport(projectId, EXISTING_SCAN_RESULT_ID, "\"Scan Result\"", Reports.Locale.RU, ReportFormatType.HTML, null);
        reportTempFile = project.generateReport(projectId, EXISTING_SCAN_RESULT_ID, "\"Scan Result\"", Reports.Locale.RU, ReportFormatType.JSON, null);
        reportTempFile = project.generateReport(projectId, EXISTING_SCAN_RESULT_ID, "\"Scan Result\"", Reports.Locale.RU, ReportFormatType.PDF, null);
        File report = TEMPREPORTFOLDER.toPath().resolve("report.json").toFile();
        // FileUtils.copyFile(issuesTempFile, issues);
        // FileUtils.forceDelete(issuesTempFile);
    }
}
