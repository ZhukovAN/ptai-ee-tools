package com.ptsecurity.appsec.ai.ee.test.scan.settings;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AiprojLegacy;
import com.ptsecurity.appsec.ai.ee.scan.settings.v411.AiProjScanSettings;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

public class AiprojLegacyTest {
    @Test
    @SneakyThrows
    public void parse() {
        InputStream inputStream = getResourceStream("json/scan/settings/settings.dast.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        AiprojLegacy settings = mapper.readValue(inputStream, AiprojLegacy.class);
        Assertions.assertNotNull(settings);
        // Assertions.assertTrue("Test project".equalsIgnoreCase(settings.getProjectName()));
    }
}
