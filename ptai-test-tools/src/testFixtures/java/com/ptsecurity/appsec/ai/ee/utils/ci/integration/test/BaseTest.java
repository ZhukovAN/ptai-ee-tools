package com.ptsecurity.appsec.ai.ee.utils.ci.integration.test;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import lombok.*;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.Objects;
import java.util.logging.LogManager;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public abstract class BaseTest {
    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class,
            property = "id")
    public static class Connection {
        protected String id;
        protected String url;
        protected String token;
        protected String user;
        protected String password;
        protected String ca;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class Configuration {
        protected Map<String, Connection> connections;
        @JsonProperty("current")
        protected Connection current;
    }

    private static Connection CONNECTION = null;

    @SneakyThrows
    public static Connection CONNECTION() {
        if (null == CONNECTION) {
            // final Yaml yaml = new Yaml();
            final InputStream inputStream = BaseTest.class.getResourceAsStream("/configuration.yaml");
            // CONFIGURATION = yaml.load(inputStream);
            final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
            Configuration configuration = objectMapper.readValue(inputStream, Configuration.class);
            CONNECTION = configuration.getCurrent();
        }
        return CONNECTION;
    }

    /**
     * Temporal folder where subfolders will be created
     */
    @TempDir
    protected Path TEMP_FOLDER;

    /**
     * Method returns InputStream that allows to read resource data
     * @param name Absolute (as {@link ClassLoader#getResourceAsStream(String)} used) name of resource
     * @return InputStream where resource data is to be read from
     */
    @SneakyThrows
    @NonNull
    public static InputStream getResourceStream(@NonNull final String name) {
        InputStream inputStream = BaseTest.class.getClassLoader().getResourceAsStream(name);
        Assertions.assertNotNull(inputStream);
        return inputStream;
    }

    @SneakyThrows
    @NonNull
    public static String getResourceString(@NonNull final String name) {
        InputStream inputStream = Objects.requireNonNull(BaseTest.class.getClassLoader().getResourceAsStream(name));
        return IOUtils.toString(inputStream, StandardCharsets.UTF_8);
    }

    /**
     * Method extracts packed resource file contents to temp folder. Currently, only 7-zip packed resources
     * are supported
     * @param name Absolute name of resource
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    public Path getPackedResourceFile(@NonNull final String name) {
        return getPackedResourceFile(name, null);
    }

    /**
     * Method extracts packed resource file contents to temp folder. Currently, only 7-zip packed resources
     * are supported
     * @param name Absolute name of resource
     * @param tempFolder Folder where resources are to be unpacked.
     *                   If null value is passed, temporal directory will be automatically created
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public Path getPackedResourceFile(@NonNull final String name, final Path tempFolder) {
        if (name.endsWith(".7z"))
            return getSevenZippedResourceFile(name, tempFolder);
        else if (name.endsWith(".zip"))
            return getZippedResourceFile(name, tempFolder);
        else
            throw new IllegalArgumentException("Unsupported packed file " + name);
    }

    /**
     * Method extracts 7z-packed resource file contents to temp folder
     * @param name Absolute name of resource
     * @param tempFolder Folder where resources are to be unpacked.
     *                   If null value is passed, temporal directory will be automatically created
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public Path getSevenZippedResourceFile(@NonNull final String name, final Path tempFolder) {
        Path res = null;
        Path rootOutputFolder = (null == tempFolder)
                ? Files.createTempDirectory(TEMP_FOLDER, "")
                : tempFolder;

        // As 7zip needs random access to packed file, there's no direct way to use
        // InputStream: we are allowed to use File or SeekableByteChannel only. So we
        // need to copy resource contents to temp file
        try (TempFile tempResourceFile = TempFile.createFile(TEMP_FOLDER)) {
            InputStream is = getResourceStream(name);
            FileUtils.copyInputStreamToFile(is, tempResourceFile.toFile());
            SevenZFile packedFile = new SevenZFile(tempResourceFile.toFile());
            byte[] buffer = new byte[1024];

            SevenZArchiveEntry entry = packedFile.getNextEntry();
            while (null != entry) {
                if (!entry.isDirectory()) {
                    File out = rootOutputFolder.resolve(entry.getName()).toFile();

                    // If this is first entry then it is to returned as a result. If there are more than one entry in the archive, folder path is to be returned
                    res = (null == res) ? out.toPath() : rootOutputFolder;

                    if (!out.getParentFile().exists() && !out.getParentFile().mkdirs()) throw new IOException("Failed to create directory " + out.getParentFile());

                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        do {
                            int dataRead = packedFile.read(buffer);
                            if (-1 == dataRead || 0 == dataRead) break;
                            fos.write(buffer, 0, dataRead);
                        } while (true);
                    }
                }
                entry = packedFile.getNextEntry();
            }
            packedFile.close();
        }
        return res;
    }

    /**
     * Method extracts zip-packed resource file contents to temp folder
     * @param name Absolute name of resource like "code/php-smoke-misc.zip"
     * @param tempFolder Folder where resources are to be unpacked.
     *                   If null value is passed, temporal directory will be automatically created
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public Path getZippedResourceFile(@NonNull final String name, final Path tempFolder) {
        Path res = null;
        Path rootOutputFolder = (null == tempFolder)
                ? Files.createTempDirectory(TEMP_FOLDER, "")
                : tempFolder;

        try (InputStream is = getResourceStream(name);
             ZipInputStream zis = new ZipInputStream(is)) {
            ZipEntry entry = zis.getNextEntry();
            while (null != entry) {
                if (!entry.isDirectory()) {
                    File out = rootOutputFolder.resolve(entry.getName()).toFile();
                    // If this is first entry then it is to returned as a result. If there are more than one entry in the archive, folder path is to be returned
                    res = (null == res) ? out.toPath() : rootOutputFolder;
                    if (!out.getParentFile().exists() && !out.getParentFile().mkdirs()) throw new IOException("Failed to create directory " + out.getParentFile());
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        IOUtils.copy(zis, fos);
                    }
                }
                entry = zis.getNextEntry();
            }
        }
        return res;
    }

    /**
     * Method creates fault-tolerant (i.e. non-sensitive to non-standard JSON features
     * like comments, case-insensitive field names etc) parser
     * @return JSON parser instance
     */
    public static ObjectMapper createFaultTolerantObjectMapper() {
        // Create IssuesModel deserializer
        ObjectMapper mapper = new ObjectMapper();
        // Need this as JSONs like aiproj settings may contain comments
        mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
        // Need this as JSON report contains "Descriptions" while IssuesModel have "descriptions"
        mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES);
        mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS);
        // Need this as JSON may contain fields that are missing from model
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    @SneakyThrows
    public static void deleteFolder(@NonNull final Path path) {
        if (!path.toFile().exists()) return;
        Files.walkFileTree(path, new FileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                Assertions.assertTrue(file.toFile().setWritable(true));
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
        FileUtils.deleteDirectory(path.toFile());
    }

    @AfterAll
    public static void fini() {
    }

    @SneakyThrows
    @BeforeAll
    public static void init() {
        InputStream stream = getResourceStream("logging.properties");
        LogManager.getLogManager().readConfiguration(stream);
    }
}
