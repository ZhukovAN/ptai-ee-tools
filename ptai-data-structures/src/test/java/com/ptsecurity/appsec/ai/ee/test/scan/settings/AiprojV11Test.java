package com.ptsecurity.appsec.ai.ee.test.scan.settings;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AiprojLegacy;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AiprojV11;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;

public class AiprojV11Test {
    @Test
    @SneakyThrows
    public void parsePhpOwaspBricks() {
        InputStream inputStream = getResourceStream("json/scan/settings/v11/settings.php-owasp-bricks.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        AiprojV11 settings = mapper.readValue(inputStream, AiprojV11.class);
        Assertions.assertNotNull(settings);
        Assertions.assertTrue("junit-php-owasp-bricks".equalsIgnoreCase(settings.getProjectName()));
    }
}
