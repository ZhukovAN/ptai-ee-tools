package com.ptsecurity.misc.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.misc.tools.helpers.ArchiveHelper;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Objects;

import static com.ptsecurity.misc.tools.helpers.ArchiveHelper.extractResourceFile;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
@DisplayName("Test archived data support tools")
class ArchiveHelperTest extends BaseTest {
    @Getter
    @Setter
    private static class TestJson {
        protected String value;
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from JSON resource file")
    public void readJsonResource() {
        InputStream inputStream = getResourceStream("data/test.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createObjectMapper();
        JsonNode json = mapper.readTree(inputStream);
        assertEquals("Test", json.get("value").textValue());
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from 7-zip-packed JSON resource file")
    public void readSevenZipPackedJsonResource() {
        Path packedFileContents = ArchiveHelper.extractResourceFile("data/test.7z");
        Assertions.assertNotNull(packedFileContents);
        try (TempFile jsonFile = new TempFile(packedFileContents)) {
            Assertions.assertTrue(jsonFile.toFile().isFile());

            ObjectMapper mapper = createObjectMapper();
            TestJson json = mapper.readValue(jsonFile.toFile(), TestJson.class);
            Assertions.assertTrue("TEST".equalsIgnoreCase(json.value));
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from zip-packed JSON resource file")
    public void readZipPackedJsonResource() {
        Path packedFileContents = Objects.requireNonNull(ArchiveHelper.extractResourceFile("data/test.zip"));
        try (TempFile jsonFile = new TempFile(packedFileContents)) {
            Assertions.assertTrue(jsonFile.toFile().isFile());

            ObjectMapper mapper = createObjectMapper();
            TestJson json = mapper.readValue(jsonFile.toFile(), TestJson.class);
            Assertions.assertTrue("TEST".equalsIgnoreCase(json.value));
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse multiple entries from 7-zip-packed JSON resource file")
    public void readSevenZipPackedJsonResources() {
        Path packedFileContents = Objects.requireNonNull(ArchiveHelper.extractResourceFile("data/tests.7z"));
        try (TempFile folder = new TempFile(packedFileContents)) {
            Assertions.assertTrue(folder.toFile().isDirectory());

            Path txtFile = folder.toPath().resolve("test.txt");
            String data = FileUtils.readFileToString(txtFile.toFile(), StandardCharsets.UTF_8);
            Assertions.assertTrue("TEST".equalsIgnoreCase(data));

            Path jsonFile = folder.toPath().resolve("test.json");
            ObjectMapper mapper = createObjectMapper();
            TestJson json = mapper.readValue(jsonFile.toFile(), TestJson.class);
            Assertions.assertTrue("TEST".equalsIgnoreCase(json.value));
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse multiple entries from zip-packed JSON resource file")
    public void readZipPackedJsonResources() {
        Path packedFileContents = Objects.requireNonNull(ArchiveHelper.extractResourceFile("data/tests.zip"));
        try (TempFile folder = new TempFile(packedFileContents)) {
            Assertions.assertTrue(folder.toFile().isDirectory());

            Path txtFile = folder.toPath().resolve("test.txt");
            String data = FileUtils.readFileToString(txtFile.toFile(), StandardCharsets.UTF_8);
            Assertions.assertTrue("TEST".equalsIgnoreCase(data));

            Path jsonFile = folder.toPath().resolve("test.json");
            ObjectMapper mapper = createObjectMapper();
            TestJson json = mapper.readValue(jsonFile.toFile(), TestJson.class);
            Assertions.assertTrue("TEST".equalsIgnoreCase(json.value));
        }
    }
}
