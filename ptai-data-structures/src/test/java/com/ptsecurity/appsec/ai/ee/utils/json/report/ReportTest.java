package com.ptsecurity.appsec.ai.ee.utils.json.report;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.Description;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue.GenericIssueMetadata;
import com.ptsecurity.appsec.ai.ee.utils.json.report.vulnerability.GenericVulnerability;
import com.ptsecurity.appsec.ai.ee.utils.json.report.vulnerability.details.Report;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@DisplayName("Check PT AI Enterprise reports helper")
class ReportTest {

    @Test
    @DisplayName("Parse correct JSON reports")
    void parseCorrectJsonReports() {
        Assertions.assertDoesNotThrow(() -> {
            loadZippedReport("json/api.projects.getIssues.json.zip");
            loadZippedReport("json/api.projects.getIssues.owasp.benchmarks.json.zip");
        });
    }

    Report loadZippedReport(String jsonFile) throws IOException {
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(jsonFile);
        ZipInputStream zis = new ZipInputStream(is);
        ZipEntry ze = zis.getNextEntry();

        String json = IOUtils.toString(zis, StandardCharsets.UTF_8);
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        Report report = jsonMapper.readValue(json, Report.class);
        for (GenericVulnerability vulnerability : report) {
            GenericIssueMetadata meta = vulnerability.getMeta();
            Description[] description = vulnerability.getDescription();
        }
        return report;
    }
}