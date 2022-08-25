package com.ptsecurity.appsec.tools.jenkins.dependencies.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.nio.file.Path;

@Slf4j
class PluginVersionsTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Parse plugin-versions.json from local resources")
    public void parsePluginVersionsJson(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        try (TempFile destination = TempFile.createFolder()) {
            Path path = extractPackedResourceFile("plugin-versions.json.7z");
            log.trace("JSON extracted to temp file {}", path);
            ObjectMapper mapper = createFaultTolerantObjectMapper();
            // mapper = new ObjectMapper();
            PluginVersions pluginVersions = mapper.readValue(path.toFile(), PluginVersions.class);
            log.trace("Plugin versions JSON parsed");

            Plugin tokenMacro = pluginVersions.getPlugins().get("token-macro").get("2.12");
            log.trace("Plugin {} found", tokenMacro);
        }
    }
}