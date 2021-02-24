package com.ptsecurity.appsec.ai.desktop.utils.xml.report.base;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter @Setter @ToString
public class DisplayName extends StringValue {
    @JacksonXmlProperty(isAttribute = true, localName = "DisplayName")
    private String displayName;
}