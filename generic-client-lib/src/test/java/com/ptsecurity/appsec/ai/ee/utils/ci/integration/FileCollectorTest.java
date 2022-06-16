package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.scan.sources.Transfer;
import com.ptsecurity.appsec.ai.ee.scan.sources.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.SystemUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.condition.OS.LINUX;

public class FileCollectorTest extends BaseTest {
    private static class Tool extends AbstractTool {

    }

    @SneakyThrows
    @Test
    @Tag("integration")
    @EnabledOnOs(LINUX)
    public void createSymlink(@TempDir final Path sources) {
        // Symlink creation under Windows requires test to be executed on behalf of Administrator, so just skip
        if (!SystemUtils.IS_OS_LINUX) return;
        createSampleFileSystem(sources);
        final String testString = UUID.randomUUID().toString();
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

    @SneakyThrows
    @Test
    public void createZip(@TempDir final Path sources) {
        createSampleFileSystem(sources);
        File zip = FileCollector.collect(null, sources.toFile(), new Tool());
        Assertions.assertTrue(zip.exists());
    }

    @SneakyThrows
    public void createSampleFileSystem(@TempDir final Path sources) {
        Path classFile = sources
                .resolve("module").resolve("submodule")
                .resolve("build").resolve("classes")
                .resolve("java").resolve("main")
                .resolve("module").resolve("submodule").resolve("Source.class");
        Path sourceFile = sources
                .resolve("module").resolve("submodule")
                .resolve("src").resolve("main")
                .resolve("java")
                .resolve("module").resolve("submodule").resolve("Source.java");
        Files.createDirectories(classFile.getParent());
        Files.write(classFile, UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        Files.createDirectories(sourceFile.getParent());
        Files.write(sourceFile, UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
    }

    @SneakyThrows
    @Test
    @DisplayName("Include / exclude Ant mask")
    public void includeAndExclude(@TempDir final Path sources) {
        createSampleFileSystem(sources);
        Transfers transfers = new Transfers();
        transfers.addTransfer(Transfer.builder()
                .excludes("./module/*/build/*/*.class")
                .build());
        FileCollector collector = new FileCollector(transfers, new Tool());
        List<FileCollector.Entry> entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(2, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());

        transfers.clear();
        transfers.addTransfer(Transfer.builder()
                .excludes("**/build/**/module/**/*.class")
                .build());
        entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(1, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());

        transfers.clear();
        transfers.addTransfer(Transfer.builder()
                .excludes("**/*.class")
                .build());
        entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(1, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());

        transfers.clear();
        transfers.addTransfer(Transfer.builder()
                .excludes("module/**/build/**/module/**/*.class")
                .build());
        entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(1, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());

        transfers.clear();
        transfers.addTransfer(Transfer.builder()
                .excludes("**/build/**/*.class")
                .build());
        entries = collector.collectFiles(sources.toFile());
        Assertions.assertEquals(1, entries.stream().map(FileCollector.Entry::getPath).filter(p -> !p.toFile().isDirectory()).count());
    }

}
