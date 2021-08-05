package com.ptsecurity.appsec.ai.ee.utils.ci.integration.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

@Slf4j
@DisplayName("Test base resources data read and parse test tools")
public class ResourcesReadTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Read data from plain text resource file")
    public void readTextResource() {
        log.debug("Trying to get test resource stream");
        InputStream inputStream = getResourceStream("data/test.txt");
        Assertions.assertNotNull(inputStream);
        log.debug("Test resource stream successfully loaded");
        String data = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
        Assertions.assertTrue("TEST".equalsIgnoreCase(data));
    }

    @Getter
    @Setter
    static class TestJson {
        protected String value;
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from JSON resource file")
    public void readJsonResource() {
        InputStream inputStream = getResourceStream("data/test.json");
        Assertions.assertNotNull(inputStream);
        ObjectMapper mapper = createFaultTolerantObjectMapper();
        TestJson json = mapper.readValue(inputStream, TestJson.class);
        Assertions.assertTrue("TEST".equalsIgnoreCase(json.value));
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse data from 7-zip-packed JSON resource file")
    public void readPackedJsonResource() {
        Path packedFileContents = getPackedResourceFile("data/test.7z");
        Assertions.assertNotNull(packedFileContents);
        try (TempFile jsonFile = new TempFile(packedFileContents)) {
            Assertions.assertTrue(jsonFile.toFile().isFile());

            ObjectMapper mapper = createFaultTolerantObjectMapper();
            TestJson json = mapper.readValue(jsonFile.toFile(), TestJson.class);
            Assertions.assertTrue("TEST".equalsIgnoreCase(json.value));
        }
    }

    @SneakyThrows
    @Test
    @DisplayName("Read and parse multiple data from 7-zip-packed JSON resource file")
    public void readPackedJsonResources() {
        Path packedFileContents = getPackedResourceFile("data/tests.7z");
        Assertions.assertNotNull(packedFileContents);
        try (TempFile folder = new TempFile(packedFileContents)) {
            Assertions.assertTrue(folder.toFile().isDirectory());

            Path txtFile = folder.toPath().resolve("test.txt");
            String data = FileUtils.readFileToString(txtFile.toFile(), StandardCharsets.UTF_8);
            Assertions.assertTrue("TEST".equalsIgnoreCase(data));

            Path jsonFile = folder.toPath().resolve("test.json");
            ObjectMapper mapper = createFaultTolerantObjectMapper();
            TestJson json = mapper.readValue(jsonFile.toFile(), TestJson.class);
            Assertions.assertTrue("TEST".equalsIgnoreCase(json.value));
        }
    }
}
