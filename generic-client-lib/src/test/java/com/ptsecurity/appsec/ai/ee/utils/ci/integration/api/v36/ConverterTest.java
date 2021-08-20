package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ProgrammingLanguage;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.V36ScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters.AiProjConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters.IssuesConverter;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@DisplayName("Test PT AI server v.3.6 REST API data structures conversion")
public class ConverterTest extends BaseTest {
    @Test
    @DisplayName("Convert DAST-only JSON scan results")
    @SneakyThrows
    public void convertDastOnlyJsonSettingsV36() {
        InputStream inputStream = getResourceStream("json/scan/settings/settings.dast.aiproj");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        AiProjScanSettings settings = mapper.readValue(inputStream, AiProjScanSettings.class).fix();

        V36ScanSettings scanSettings = AiProjConverter.convert(settings, new ArrayList<>(), new ArrayList<>());
        Assertions.assertTrue(V36ProgrammingLanguage.JAVA == scanSettings.getProgrammingLanguage());
    }
}
