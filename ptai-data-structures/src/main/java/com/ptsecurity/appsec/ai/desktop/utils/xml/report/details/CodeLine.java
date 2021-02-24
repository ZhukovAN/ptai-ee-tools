package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.base.IntValue;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.base.StringValue;
import lombok.Getter;

import java.util.List;

@Getter
public class CodeLine {
    @JsonProperty("LineType")
    protected StringValue lineType;
    @JsonProperty("LineNumber")
    protected IntValue lineNumber;
    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("CodeLinePart")
    protected List<CodeLinePart> codeLinePart;
}
