package com.ptsecurity.appsec.ai.desktop.utils.xml.report.glossary;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import lombok.Getter;

import java.util.List;

@Getter
public class Glossary {
    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("Type")
    protected List<GlossaryItem> type;
}
