package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import org.apache.commons.io.FilenameUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils.setFilenameExtension;

public class ReportUtilsTest {
    @Test
    public void getFilenameExtensionTest() {
        String extension = FilenameUtils.getExtension("report");
        Assertions.assertEquals("", extension);
        extension = FilenameUtils.getExtension("report.");
        Assertions.assertEquals("", extension);
        extension = FilenameUtils.getExtension("report.html");
        Assertions.assertEquals("html", extension);
        extension = FilenameUtils.getExtension("report.en.json");
        Assertions.assertEquals("json", extension);
        extension = FilenameUtils.getExtension(".en.json");
        Assertions.assertEquals("json", extension);
        extension = FilenameUtils.getExtension(".json");
        Assertions.assertEquals("json", extension);
    }

    @Test
    public void setFilenameExtensionTest() {
        String filename = setFilenameExtension("report", "html");
        Assertions.assertEquals("report.html", filename);
        filename = setFilenameExtension("report.", "html");
        Assertions.assertEquals("report.html", filename);
        filename = setFilenameExtension("report.json", "html");
        Assertions.assertEquals("report.html", filename);
        filename = setFilenameExtension("report.en.json", "html");
        Assertions.assertEquals("report.en.html", filename);
        filename = setFilenameExtension(".en.json", "html");
        Assertions.assertEquals(".en.html", filename);
    }
}
