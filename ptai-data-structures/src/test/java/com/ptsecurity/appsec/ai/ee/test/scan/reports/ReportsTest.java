package com.ptsecurity.appsec.ai.ee.test.scan.reports;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.io.JsonEOFException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@DisplayName("Read and parse data from report definitions JSON resource file")
public class ReportsTest extends BaseTest {
    @Test
    @SneakyThrows
    @DisplayName("Load generic report definition from reports.1.json")
    public void loadGenericReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.1.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        Reports reports = mapper.readValue(inputStream, Reports.class);

        Assertions.assertNotNull(reports);
        Assertions.assertEquals(1, reports.getReport().size());
        Assertions.assertEquals(2, reports.getData().size());
        Assertions.assertEquals(1, reports.getRaw().size());

        Assertions.assertEquals(Reports.Report.Format.HTML, reports.getReport().get(0).format);
        Assertions.assertEquals(Reports.Data.Format.XML, reports.getData().get(1).format);
    }

    @Test
    @SneakyThrows
    @DisplayName("Fail invalid report definition from reports.2.json")
    public void failInvalidReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.2.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        Assertions.assertThrows(JsonEOFException.class, () -> mapper.readValue(inputStream, Reports.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Ignore non-existent report template name from reports.3.json")
    public void ignoreMissingReportTemplateReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.3.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        Assertions.assertDoesNotThrow(() -> mapper.readValue(inputStream, Reports.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Fail confirmationStatuses typo in reports.4.json")
    public void failTypoInReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.4.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        Assertions.assertThrows(MismatchedInputException.class, () -> mapper.readValue(inputStream, Reports.class));
    }

    @Test
    @SneakyThrows
    @DisplayName("Load filtered report definition with case-insensitive enum values from reports.5.json")
    public void loadFilteredReportDefinition() {
        InputStream inputStream = getResourceStream("json/scan/reports/reports.5.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        Reports reports = mapper.readValue(inputStream, Reports.class);

        Assertions.assertNotNull(reports);
        Assertions.assertEquals(1, reports.getReport().size());
        Assertions.assertNotNull(reports.getReport().get(0).getFilters());
        Set<Reports.IssuesFilter.Level> levels = Arrays.stream(reports.getReport().get(0).getFilters().getIssueLevels()).collect(Collectors.toSet());
        Assertions.assertEquals(2, levels.size());
        Assertions.assertTrue(levels.contains(Reports.IssuesFilter.Level.MEDIUM));
        Assertions.assertTrue(levels.contains(Reports.IssuesFilter.Level.HIGH));
    }

}
