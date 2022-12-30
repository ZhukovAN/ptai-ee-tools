package com.ptsecurity.appsec.ai.ee.test.scan.reports;

import com.fasterxml.jackson.core.io.JsonEOFException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.misc.tools.BaseTest;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

@Slf4j
@DisplayName("Read and parse data from report definitions JSON resource file")
public class ReportsTest extends BaseTest {
    @Test
    @SneakyThrows
    @DisplayName("Load generic report definition from reports.1.json")
    public void loadGenericReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.1.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        Reports reports = mapper.readValue(inputStream, Reports.class);

        Assertions.assertNotNull(reports);
        Assertions.assertEquals(1, reports.getReport().size());
        Assertions.assertEquals(1, reports.getRaw().size());

        Assertions.assertEquals("report.ru.html", reports.getReport().get(0).getFileName());
    }

    @Test
    @SneakyThrows
    @DisplayName("Fail invalid report definition from reports.2.json")
    public void failInvalidReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.2.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        Assertions.assertThrows(JsonEOFException.class, () -> mapper.readValue(inputStream, Reports.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Ignore non-existent report template name from reports.3.json")
    public void ignoreMissingReportTemplateReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.3.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        Assertions.assertDoesNotThrow(() -> mapper.readValue(inputStream, Reports.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Fail confirmationStatuses typo in reports.4.json")
    public void failTypoInReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.4.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        Assertions.assertThrows(MismatchedInputException.class, () -> mapper.readValue(inputStream, Reports.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load filtered report definition with case-insensitive enum values from reports.5.json")
    public void loadFilteredReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.5.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        Reports reports = mapper.readValue(inputStream, Reports.class);

        Assertions.assertNotNull(reports);
        Assertions.assertEquals(1, reports.getReport().size());
        Assertions.assertNotNull(reports.getReport().get(0).getFilters());
        Set<Reports.IssuesFilter.Level> levels = new HashSet<>(reports.getReport().get(0).getFilters().getIssueLevels());
        Assertions.assertEquals(2, levels.size());
        Assertions.assertTrue(levels.contains(Reports.IssuesFilter.Level.MEDIUM));
        Assertions.assertTrue(levels.contains(Reports.IssuesFilter.Level.HIGH));
    }
}
