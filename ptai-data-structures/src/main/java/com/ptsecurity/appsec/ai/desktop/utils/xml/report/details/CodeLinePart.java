package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.base.StringValue;
import lombok.Getter;

@Getter
public class CodeLinePart extends StringValue {
    @JsonProperty("PartType")
    protected StringValue partType;
}
