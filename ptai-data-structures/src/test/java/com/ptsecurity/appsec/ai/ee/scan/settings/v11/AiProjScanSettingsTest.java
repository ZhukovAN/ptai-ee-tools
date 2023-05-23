package com.ptsecurity.appsec.ai.ee.scan.settings.v11;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;
import static org.junit.jupiter.api.Assertions.*;

class AiProjScanSettingsTest {
    @Test
    public void test() {
        String data = getResourceString("json/scan/settings/v11/settings.php-owasp-bricks.json");
        Object aiproj = Configuration.defaultConfiguration().jsonProvider().parse(data);
        String version = JsonPath.read(aiproj, "$.Version");
        assertEquals(version, "1.1");
        Object mailingSettings = JsonPath.read(aiproj, "$.MailingProjectSettings");
        Boolean mailingEnabled = JsonPath.read(mailingSettings, "$.Enabled");
        assertFalse(mailingEnabled);
        List<String> recipients = JsonPath.read(mailingSettings, "$.EmailRecipients");
        assertTrue(recipients.isEmpty());
    }

}