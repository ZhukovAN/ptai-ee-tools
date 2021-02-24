package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import lombok.Getter;
import org.apache.commons.io.FileUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class TempDirectory implements AutoCloseable {
    @Getter
    private final Path file;

    public TempDirectory() throws IOException {
        file = Files.createTempDirectory("PTAI_");
    }

    @Override
    public void close() throws Exception {
        FileUtils.deleteDirectory(file.toFile());
    }
}