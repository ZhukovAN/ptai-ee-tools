package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
class BaseJsonHelperTest extends BaseTest {

    @Test
    public void replaceMacro() {
        String json = getResourceString("json/scan/settings/settings.minimal.aiproj");
        json = BaseJsonHelper.replaceMacro(json, (s) -> { return "value: " + s; });
        log.trace(json);
    }
}