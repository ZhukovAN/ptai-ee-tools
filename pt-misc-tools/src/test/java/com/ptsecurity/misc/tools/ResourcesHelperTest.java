package com.ptsecurity.misc.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceStream;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
@DisplayName("Test base resources data read and parse test tools")
class ResourcesHelperTest extends BaseTest {
    @SneakyThrows
    @Test
    @DisplayName("Read data from plain text resource file")
    public void readTextResource() {
        log.debug("Trying to get test resource stream");
        InputStream inputStream = Objects.requireNonNull(getResourceStream("data/test.txt"));
        log.debug("Test resource stream successfully loaded");
        String data = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
        Assertions.assertTrue("TEST".equalsIgnoreCase(data));
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
}
