package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.ptai.server.auth.JSON;
import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.logging.LogManager;

public class BaseTest {
    /**
     * Temporal folder where subfolders will be created: for
     * unzipped sources, for modified JSON-defined policy / scan settings
     * and for generated reports. These folders will be initialized during {@link #init()} method call
     */
    @TempDir
    protected Path TEMP_FOLDER;
    /**
     * Temporal folder where modified JSON-defined policy / scan settings will be saved
     */
    protected Path JSON_FOLDER;

    protected static final String PEM_RESOURCE = "keys/domain.org.pem";
    protected static String PEM = null;

    /**
     * @param name Absolute (as {@link ClassLoader#getResourceAsStream(String)} used) name of resource
     * @return
     */
    @SneakyThrows
    @NonNull
    public static InputStream getResourceStream(@NonNull final String name) {
        return BaseTest.class.getClassLoader().getResourceAsStream(name);
    }

    public Path getPackedResourceFile(@NonNull final String name) {
        return getPackedResourceFile(name, null);
    }

    @SneakyThrows
    public Path getPackedResourceFile(@NonNull final String name, final Path tempFolder) {
        if (name.endsWith(".7z"))
            return getSevenZippedResourceFile(name, tempFolder);
        else
            throw new IllegalArgumentException("Unsupported packed file " + name);
    }

    @SneakyThrows
    public Path getSevenZippedResourceFile(@NonNull final String name, final Path tempFolder) {
        Path res = null;
        Path rootOutputFolder = (null == tempFolder)
                ? Files.createTempDirectory(TEMP_FOLDER, "")
                : tempFolder;

        // As 7zip needs random access to packed file, there's no direct way to use
        // InputStream: we are allowed to use File or SeekableByteChannel only. So we
        // need to copy resource contents to temp file
        InputStream is = getResourceStream(name);
        Path tempResourceFile = Files.createTempFile(TEMP_FOLDER, "", "");
        FileUtils.copyInputStreamToFile(is, tempResourceFile.toFile());
        SevenZFile packedFile = new SevenZFile(tempResourceFile.toFile());
        byte[] buffer = new byte[1024];

        SevenZArchiveEntry entry = packedFile.getNextEntry();
        while (null != entry) {
            if (!entry.isDirectory()) {
                Path out = rootOutputFolder.resolve(entry.getName());
                if (null == res)
                    // If this is first entry then it is to returned as a result
                    res = out;
                else
                    // There are more then one entry in the archive, folder path is to be returned
                    res = rootOutputFolder;

                try (FileOutputStream fos = new FileOutputStream(out.toFile())) {
                    do {
                        int dataRead = packedFile.read(buffer, 0, buffer.length);
                        if (-1 == dataRead || 0 == dataRead) break;
                        fos.write(buffer, 0, dataRead);
                    } while (true);
                }
            }
            entry = packedFile.getNextEntry();
        }
        return res;
    }

    @SneakyThrows
    @BeforeAll
    public static void init() {
        InputStream stream = BaseTest.class.getResourceAsStream("/logging.properties");
        LogManager.getLogManager().readConfiguration(stream);

        PEM = IOUtils.toString(getResourceStream(PEM_RESOURCE), StandardCharsets.UTF_8);
    }

    @AfterAll
    public static void fini() {
    }
    @SneakyThrows
    @BeforeEach
    public void pre() {
        JSON_FOLDER = TEMP_FOLDER.resolve("json");
    }

}
