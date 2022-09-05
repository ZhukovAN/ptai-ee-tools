package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
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

    public static TempFile createFile() throws GenericException {
        return createFile(null);
    }

    public static TempFile createFolder() throws GenericException {
        return createFolder(null);
    }

    public static TempFile createFile(final Path folder) throws GenericException {
        return call(() -> (null == folder)
                ? new TempFile(Files.createTempFile(PREFIX, SUFFIX))
                : new TempFile(Files.createTempFile(folder, PREFIX, SUFFIX)), "Temporal file create failed");
    }

    public static TempFile createFolder(final Path folder) throws GenericException {
        return call(() -> (null == folder)
                ? new TempFile(Files.createTempDirectory(PREFIX))
                : new TempFile(Files.createTempDirectory(folder, PREFIX)), "Temporal folder create failed");
    }

    @Override
    public void close() throws GenericException {
        if (path.toFile().isDirectory())
            call(() -> {
                FileUtils.deleteDirectory(path.toFile());
                log.trace("Temporary folder {} deleted", path);
            }, "Temporal folder delete on close failed");
        else
            call(() -> {
                FileUtils.forceDelete(path.toFile());
                log.trace("Temporary file {} deleted", path);
            }, "Temporal file delete on close failed");
    }
}
