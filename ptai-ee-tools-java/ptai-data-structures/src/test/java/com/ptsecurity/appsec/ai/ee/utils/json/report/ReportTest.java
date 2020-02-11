package com.ptsecurity.appsec.ai.ee.utils.json.report;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.Description;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue.GenericIssueMetadata;
import com.ptsecurity.appsec.ai.ee.utils.json.report.vulnerability.GenericVulnerability;
import com.ptsecurity.appsec.ai.ee.utils.json.report.vulnerability.details.Report;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;


import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.LocalizedDescription.EN;

class ReportTest {

    @Test
    void testJsonParse() throws IOException {
        Report report = testJsonReport("json/api.projects.getIssues.json");
        report = testJsonReport("json/api.projects.getIssues.owasp.benchmarks.json");
    }

    Report testJsonReport(String jsonFile) throws IOException {
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(jsonFile);
        String json = IOUtils.toString(is, StandardCharsets.UTF_8);
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        Report report = jsonMapper.readValue(json, Report.class);
        for (GenericVulnerability vulnerability : report) {
            GenericIssueMetadata meta = vulnerability.getMeta();
            Description[] description = vulnerability.getDescription();
            // Description description = vulnerability.getDescription();
            System.out.println(description[0].getValues().get(EN).getHeader());
            System.out.println(description[0].getValues().get(EN).getDescription());
        }
        return report;
    }
}