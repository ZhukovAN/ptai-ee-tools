package com.ptsecurity.appsec.ai.desktop.utils.report.generator.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;

import java.util.List;

public class Glossary {
    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("Type")
    List<GlossaryItem> type;
}
