package com.ptsecurity.appsec.tools.jenkins.dependencies.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.junit.jupiter.api.*;

import java.io.FileInputStream;
import java.net.URL;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Slf4j
class PluginVersionsTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Check version compare function")
    public void compareVersions() {
        Assertions.assertEquals(-1, PluginVersions.compareVersion("1.0", "2.14"));
        Assertions.assertEquals(-1, PluginVersions.compareVersion("2.150.3", "2.164.2"));
        Assertions.assertEquals(-1, PluginVersions.compareVersion("2.12.3", "2.13.0-230.v59243c64b0a5"));
        Assertions.assertEquals(1, PluginVersions.compareVersion("2.12.3", "2.8.11.2"));
        Assertions.assertEquals(-1, PluginVersions.compareVersion("2.13.0-230.v59243c64b0a5", "2.13.1-246.va8a9f3eaf46a"));
    }

    @SneakyThrows
    @Test
    @DisplayName("Parse plugin-versions.json from local resources")
    public void parsePluginVersionsJson(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        try (TempFile ignored = TempFile.createFolder()) {
            Path path = extractPackedResourceFile("plugin-versions.json.7z");
            log.trace("JSON extracted to temp file {}", path);
            Assertions.assertDoesNotThrow(() -> PluginVersions.load(new FileInputStream(path.toFile())));
            log.trace("Plugin versions JSON parsed");
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Collect plugin dependencies")
    public void collectPluginDependencies(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        try (TempFile ignored = TempFile.createFolder()) {
            Path path = extractPackedResourceFile("plugin-versions.json.7z");
            log.trace("JSON extracted to temp file {}", path);
            PluginVersions pluginVersions = Assertions.assertDoesNotThrow(() -> PluginVersions.load(new FileInputStream(path.toFile())));
            log.trace("Plugin versions JSON parsed");

            Plugin plugin = pluginVersions.getPlugins().get("token-macro").get("2.12");
            log.trace("Plugin {} found", plugin);

            log.trace("Check there's no token-macro support for early Jenkins version");
            Set<Plugin> plugins = pluginVersions.requiredPlugins("token-macro", "1.200.1");
            Assertions.assertNull(plugins);

            log.trace("Check token-macro 2.12 is the latest version that supports Jenkins 2.150.3");
            plugins = pluginVersions.requiredPlugins("token-macro", "2.150.3");
            Assertions.assertTrue(plugins.stream().anyMatch((p) -> p.getName().equals("token-macro") && p.getVersion().equals("2.12")));

            log.trace("Check there's no structs 1.5 that required by workflow-step-api as token-macro 2.12 already provide 1.14");
            Assertions.assertTrue(plugins.stream().noneMatch((p) -> p.getName().equals("structs") && p.getVersion().equals("1.5")));
            Assertions.assertTrue(plugins.stream().anyMatch((p) -> p.getName().equals("structs") && p.getVersion().equals("1.14")));

            log.trace("Check workflow-step-api 2.14 is required for token-macro 2.12");
            Assertions.assertTrue(plugins.stream().anyMatch((p) -> p.getName().equals("workflow-step-api") && p.getVersion().equals("2.14")));
        }
    }

    @SneakyThrows
    @Test
    @Tag("development")
    @DisplayName("Download plugin and all the required HPIs")
    public void downloadPluginWithDependencies(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        try (TempFile ignored = TempFile.createFolder()) {
            Path path = extractPackedResourceFile("plugin-versions.json.7z");
            log.trace("JSON extracted to temp file {}", path);
            PluginVersions pluginVersions = Assertions.assertDoesNotThrow(() -> PluginVersions.load(new FileInputStream(path.toFile())));
            log.trace("Plugin versions JSON parsed");

            for (String pluginName : new String[] { "token-macro", "git", "workflow-aggregator" }) {
                Set<Plugin> plugins = pluginVersions.requiredPlugins(pluginName, "2.150.3");
                try (TempFile tempFolder = TempFile.createFolder()) {
                    for (Plugin plugin : plugins) {
                        String fileName = FilenameUtils.getName(plugin.getUrl());
                        FileUtils.copyURLToFile(
                                new URL(plugin.getUrl()),
                                tempFolder.toPath().resolve(fileName).toFile());
                    }
                    log.trace("All {} plugin dependencies are saved to {}", pluginName, tempFolder);
                }
            }
        }
    }
    @SneakyThrows
    @Test
    @Tag("development")
    @DisplayName("Download plugin set and all the required HPIs")
    public void downloadPluginSetWithDependencies(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        try (TempFile ignored = TempFile.createFolder()) {
            Path path = extractPackedResourceFile("plugin-versions.json.7z");
            log.trace("JSON extracted to temp file {}", path);
            PluginVersions pluginVersions = Assertions.assertDoesNotThrow(() -> PluginVersions.load(new FileInputStream(path.toFile())));
            log.trace("Plugin versions JSON parsed");

            // Set<Plugin> plugins = pluginVersions.requiredPlugins(new HashSet<>(Arrays.asList("git", "token-macro", "credentials", "workflow-aggregator")), "2.332.1");
            Set<Plugin> plugins = pluginVersions.requiredPlugins(new HashSet<>(Arrays.asList("caffeine-api", "snakeyaml-api", "git", "token-macro", "credentials", "workflow-aggregator")), "2.150.3");
            try (TempFile tempFolder = TempFile.createFolder()) {
                for (Plugin plugin : plugins) {
                    System.out.println(plugin.getUrl());
                    String fileName = FilenameUtils.getName(plugin.getUrl());
                    FileUtils.copyURLToFile(
                            new URL(plugin.getUrl()),
                            tempFolder.toPath().resolve(fileName).toFile());
                }
                log.trace("All plugins dependencies are saved to {}", tempFolder);
            }
        }
    }
}