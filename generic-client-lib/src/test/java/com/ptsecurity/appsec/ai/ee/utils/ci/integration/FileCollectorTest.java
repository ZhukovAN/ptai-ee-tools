package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

public class FileCollectorTest extends BaseTest {
    private static class Tool extends AbstractTool {

    }

    @SneakyThrows
    @Test
    @Tag("advanced")
    public void createSymlink() {
        final String testString = UUID.randomUUID().toString();
        Path sources = getPackedResourceFile("code/java-app01.7z");
        Path docs = Files.createDirectory(sources.resolve("docs"));
        Files.write(docs.resolve("DOC"), testString.getBytes(StandardCharsets.UTF_8));
        Files.createSymbolicLink(sources.resolve("DOC.link"), docs.resolve("DOC"));
        Assertions.assertEquals(testString, FileUtils.readFileToString(sources.resolve("DOC.link").toFile(), StandardCharsets.UTF_8));

        Files.write(sources.resolve("ROOT"), testString.getBytes(StandardCharsets.UTF_8));
        Files.createSymbolicLink(docs.resolve("ROOT.link"), sources.resolve("ROOT"));

        Files.write(sources.resolve("MISSING"), testString.getBytes(StandardCharsets.UTF_8));
        Files.createSymbolicLink(docs.resolve("MISSING.link"), sources.resolve("MISSING"));

        Files.delete(sources.resolve("MISSING"));

        File zip = FileCollector.collect(null, sources.toFile(), new Tool());
        Assertions.assertTrue(zip.exists());
    }
}
