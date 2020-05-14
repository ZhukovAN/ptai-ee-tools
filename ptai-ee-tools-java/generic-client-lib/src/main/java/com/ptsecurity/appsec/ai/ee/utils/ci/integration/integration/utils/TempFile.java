package com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.utils;

import lombok.Getter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class TempFile implements AutoCloseable {
    @Getter
    private final Path file;

    public TempFile() throws IOException {
        file = Files.createTempFile("PTAI_", null);
    }

    @Override
    public void close() throws Exception {
        Files.deleteIfExists(file);
    }
}
