package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsTestHelper;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.nio.file.Files;
import java.util.UUID;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.PHP;

public abstract class BaseJsonIT extends BaseCliAstIT {
    @SneakyThrows
    @BeforeEach
    @Override
    public void pre() {
        super.pre();
    }
}