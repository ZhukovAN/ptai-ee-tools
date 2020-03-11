package com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.rest;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

class FreeStyleBuildTest {
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Build {
        @JsonProperty("number")
        protected int number;
        @JsonProperty("queueId")
        protected int queueId;
    }
    @Test
    public void deserialize() throws IOException {
        String xml = IOUtils.toString(
                getClass().getClassLoader().getResourceAsStream("xml/FreeStyleBuild.xml"),
                StandardCharsets.UTF_8.name());
        XmlMapper mapper = new XmlMapper();
        Build build = mapper.readValue(xml, Build.class);
    }

}