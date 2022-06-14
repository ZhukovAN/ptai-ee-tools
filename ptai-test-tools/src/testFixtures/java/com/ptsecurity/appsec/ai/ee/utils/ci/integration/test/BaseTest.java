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
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.compress.archivers.sevenz.SevenZOutputFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.logging.LogManager;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Slf4j
public abstract class BaseTest {

    public static final String JAVA_APP01_PROJECT_NAME = "junit-java-app01";
    public static final String JAVA_OWASP_BENCHMARK_PROJECT_NAME = "junit-java-owasp-benchmark";
    public static final String PHP_OWASP_BRICKS_PROJECT_NAME = "junit-php-owasp-bricks";
    public static final String PHP_SMOKE_MISC_PROJECT_NAME = "junit-php-smoke-misc";
    public static final String PHP_SMOKE_MEDIUM_PROJECT_NAME = "junit-php-smoke-medium";
    public static final String PHP_SMOKE_HIGH_PROJECT_NAME = "junit-php-smoke-high";
    public static final String PHP_SMOKE_MULTIFLOW_PROJECT_NAME = "junit-php-smoke-multiflow";

    public static final String[] ALL_PROJECT_NAMES = new String[] { JAVA_APP01_PROJECT_NAME, JAVA_OWASP_BENCHMARK_PROJECT_NAME, PHP_OWASP_BRICKS_PROJECT_NAME, PHP_SMOKE_MISC_PROJECT_NAME, PHP_SMOKE_MEDIUM_PROJECT_NAME, PHP_SMOKE_HIGH_PROJECT_NAME, PHP_SMOKE_MULTIFLOW_PROJECT_NAME };

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class,
            property = "id")
    public static class Connection {
        public enum Version {
            V36, V40
        }
        protected String id;
        protected Version version;
        protected String url;
        protected String token;
        protected String user;
        protected String password;
        protected String ca;
        protected boolean insecure;

        public String getCaPem() {
            return getResourceString(CONNECTION().getCa());
        }
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
            final InputStream inputStream = BaseTest.class.getResourceAsStream("/configuration.yml");
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
    private static Path TEMP_FOLDER;

    static {
        Assertions.assertDoesNotThrow(() -> TEMP_FOLDER = Files.createTempDirectory("ptai-"));
    }

    public static Path TEMP_FOLDER() {
        Assertions.assertNotNull(TEMP_FOLDER);
        return TEMP_FOLDER;
    }

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
    @SneakyThrows
    public static Path extractPackedResourceFile(@NonNull final String name) {
        return extractPackedResourceFile(name, Files.createTempDirectory(TEMP_FOLDER, ""));
    }

    /**
     * Method extracts packed resource file contents to temp folder. Currently, only 7-zip packed resources
     * are supported
     * @param name Absolute name of resource
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extractPackedResourceFile(@NonNull final String name, @NonNull final Path destinationFolder) {
        if (name.endsWith(".7z"))
            return extractSevenZippedResourceFile(name, destinationFolder);
        else if (name.endsWith(".zip"))
            return extractZippedResourceFile(name, destinationFolder);
        else
            throw new IllegalArgumentException("Unsupported packed file " + name);
    }

    /**
     * Method extracts 7z-packed resource file contents to temp folder
     * @param name Absolute name of resource
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extractSevenZippedResourceFile(@NonNull final String name) {
        return extractSevenZippedResourceFile(name, Files.createTempDirectory(TEMP_FOLDER, ""));
    }

    /**
     * Method extracts 7z-packed resource file contents to temp folder
     * @param name Absolute name of resource
     * @param destinationFolder Folder where resources are to be unpacked.
     *                   If null value is passed, temporal directory will be automatically created
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extractSevenZippedResourceFile(@NonNull final String name, @NonNull final Path destinationFolder) {
        Path res = null;

        // As 7zip needs random access to packed file, there's no direct way to use
        // InputStream: we are allowed to use File or SeekableByteChannel only. So we
        // need to copy resource contents to auto-closeable temp file
        try (TempFile tempResourceFile = TempFile.createFile()) {
            InputStream is = getResourceStream(name);
            FileUtils.copyInputStreamToFile(is, tempResourceFile.toFile());
            SevenZFile packedFile = new SevenZFile(tempResourceFile.toFile());
            byte[] buffer = new byte[1024];

            SevenZArchiveEntry entry = packedFile.getNextEntry();
            while (null != entry) {
                if (!entry.isDirectory()) {
                    File out = destinationFolder.resolve(entry.getName()).toFile();

                    // If this is first entry then it is to returned as a result. If there are more than one entry in the archive, folder path is to be returned
                    res = (null == res) ? out.toPath() : destinationFolder;

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
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public Path extractZippedResourceFile(@NonNull final String name) {
        return extractZippedResourceFile(name, Files.createTempDirectory(TEMP_FOLDER, ""));
    }

    /**
     * Method extracts zip-packed resource file contents to temp folder
     * @param name Absolute name of resource like "code/php-smoke-misc.zip"
     * @param destinationFolder Folder where resources are to be unpacked.
     *                   If null value is passed, temporal directory will be automatically created
     * @return Path to extracted resources. If packed resource contains exactly one file then path
     * to extracted file will be returned. If resource contains more than one file all these files
     * will be extracted to destination folder and its path will be returned
     */
    @SneakyThrows
    public static Path extractZippedResourceFile(@NonNull final String name, final Path destinationFolder) {
        Path res = null;

        try (InputStream is = getResourceStream(name);
             ZipInputStream zis = new ZipInputStream(is)) {
            ZipEntry entry = zis.getNextEntry();
            while (null != entry) {
                if (!entry.isDirectory()) {
                    File out = destinationFolder.resolve(entry.getName()).toFile();
                    // If this is first entry then it is to returned as a result. If there are more than one entry in the archive, folder path is to be returned
                    res = (null == res) ? out.toPath() : destinationFolder;
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

    @SneakyThrows
    public static void sevenZipData(@NonNull final Path path, final byte[] data) {
        String name = path.getFileName().toString().trim();
        if (name.endsWith(".7z"))
            name = name.substring(0, name.length() - ".7z".length());
        sevenZipData(path, name, data);
    }

    @SneakyThrows
    public static void sevenZipData(@NonNull final Path path, @NonNull final String name, final byte[] data) {
        if (!path.toFile().exists()) Files.createFile(path);
        try (SevenZOutputFile zip = new SevenZOutputFile(path.toFile())) {
            SevenZArchiveEntry entry = new SevenZArchiveEntry();
            entry.setName(name);
            entry.setDirectory(false);
            entry.setLastModifiedDate(new Date());
            entry.setSize(data.length);
            zip.putArchiveEntry(entry);
            zip.write(data);
            zip.closeArchiveEntry();
        };
    }

    @SneakyThrows
    public static String extractSevenZippedSingleStringFromResource(@NonNull final String name) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] data = IOUtils.resourceToByteArray(name, BaseTest.class.getClassLoader());
        SevenZFile packedFile = new SevenZFile(new SeekableInMemoryByteChannel(data));
        byte[] buffer = new byte[1024];

        SevenZArchiveEntry entry = packedFile.getNextEntry();
        while (null != entry) {
            if (entry.isDirectory()) {
                log.trace("Skip {} entry as is is a directory", entry.getName());
                entry = packedFile.getNextEntry();
                continue;
            }
            do {
                int dataRead = packedFile.read(buffer);
                if (-1 == dataRead || 0 == dataRead) break;
                result.write(buffer, 0, dataRead);
            } while (true);
            return result.toString();
        }
        return null;
    }
}
