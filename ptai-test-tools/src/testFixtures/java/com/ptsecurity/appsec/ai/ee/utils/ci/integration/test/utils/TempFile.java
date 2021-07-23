package com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils;

import lombok.AllArgsConstructor;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@AllArgsConstructor
public class TempFile implements AutoCloseable {
    public static final String PREFIX = "ptai-";
    public static final String SUFFIX = "-file";

    private final Path path;

    public Path toPath() {
        return path;
    }

    public File toFile() {
        return path.toFile();
    }

    public static TempFile createFile(final Path folder) throws IOException {
        return (null == folder)
                ? new TempFile(Files.createTempFile(PREFIX, SUFFIX))
                : new TempFile(Files.createTempFile(folder, PREFIX, SUFFIX));
    }

    public static TempFile createFolder(final Path folder) throws IOException {
        return (null == folder)
                ? new TempFile(Files.createTempDirectory(PREFIX))
                : new TempFile(Files.createTempDirectory(folder, PREFIX));
    }

    @Override
    public void close() throws Exception {
        if (path.toFile().isDirectory())
            FileUtils.deleteDirectory(path.toFile());
        else
            FileUtils.forceDelete(path.toFile());
    }
}
