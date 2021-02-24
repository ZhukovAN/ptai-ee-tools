package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.base.StringValue;
import lombok.Getter;

import java.util.List;

@Getter
public class DataFlowElement {
    @JsonProperty("FileName")
    protected StringValue fileName;
    @JsonProperty("FullPath")
    protected StringValue fullPath;
    @JsonProperty("EntryType")
    protected StringValue entryType;
    @JsonProperty("EntryTypeDisplayValue")
    protected StringValue entryTypeDisplayValue;

    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("CodeLine")
    protected List<CodeLine> codeLine;
}
