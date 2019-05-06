package com.ptsecurity.appsec.ai.desktop.utils.report.generator.domain;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class BaseDisplayName {
    @JacksonXmlProperty(isAttribute = true, localName = "DisplayName")
    private String displayName;
    @JacksonXmlText
    private String value;
}
