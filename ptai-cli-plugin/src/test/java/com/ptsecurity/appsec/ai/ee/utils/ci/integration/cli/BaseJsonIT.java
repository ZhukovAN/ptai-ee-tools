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
    protected String newProjectName;

    protected JsonSettingsTestHelper scanPhpSettings;
    protected String scanPolicy;

    @SneakyThrows
    protected String savedScanSettingsPath() {
        Assertions.assertNotNull(scanPhpSettings);
        File scanSettingsFile = Files.createTempFile(TEMP_FOLDER, "ptai-", "-settings").toFile();
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        mapper.writeValue(scanSettingsFile, scanPhpSettings);
        return scanSettingsFile.getAbsolutePath();
    }

    @SneakyThrows
    protected String savedScanPolicyPath() {
        Assertions.assertNotNull(scanPolicy);
        File scanPolicyFile = Files.createTempFile(TEMP_FOLDER, "ptai-", "-policy").toFile();
        ObjectMapper mapper = BaseJsonHelper.createObjectMapper();
        mapper.writeValue(scanPolicyFile, scanPolicy);
        return scanPolicyFile.getAbsolutePath();
    }
    
    @SneakyThrows
    @BeforeEach
    @Override
    public void pre() {
        super.pre();
        newProjectName = "junit-" + UUID.randomUUID();

        String jsonSettings = getResourceString("json/scan/settings/settings.minimal.aiproj");
        Assertions.assertFalse(StringUtils.isEmpty(jsonSettings));

        scanPhpSettings = new JsonSettingsTestHelper(jsonSettings);
        scanPhpSettings.setProgrammingLanguage(PHP);

        scanPolicy = getResourceString("json/scan/settings/policy.generic.json");
        Assertions.assertFalse(StringUtils.isEmpty(scanPolicy));
    }
}