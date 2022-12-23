package com.ptsecurity.misc.tools;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

@Slf4j
@AllArgsConstructor
public class TempFile implements AutoCloseable {
    private static final String PREFIX = "pt-";
    private static final String SUFFIX = "";

    private final Path path;

    @Override
    public String toString() {
        return path.toString();
    }

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
        TempFile result = call(() -> (null == folder)
                ? new TempFile(Files.createTempFile(PREFIX, SUFFIX))
                : new TempFile(Files.createTempFile(folder, PREFIX, SUFFIX)), "Temporary file create failed");
        log.trace("Temporary file {} created", result.path);
        return result;
    }

    public static TempFile createFolder(final Path folder) throws GenericException {
        TempFile result = call(() -> (null == folder)
                ? new TempFile(Files.createTempDirectory(PREFIX))
                : new TempFile(Files.createTempDirectory(folder, PREFIX)), "Temporary folder create failed");
        log.trace("Temporary folder {} created", result.path);
        return result;
    }

    @Override
    public void close() throws GenericException {
        if (path.toFile().isDirectory())
            call(() -> {
                FileUtils.deleteDirectory(path.toFile());
                log.trace("Temporary folder {} deleted", path);
            }, "Temporary folder delete on close failed");
        else
            call(() -> {
                FileUtils.forceDelete(path.toFile());
                log.trace("Temporary file {} deleted", path);
            }, "Temporary file delete on close failed");
    }
}
