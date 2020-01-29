package com.ptsecurity.appsec.ai.desktop.utils.report.generator.domain;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class Level extends BaseDisplayName {
    @JacksonXmlProperty(isAttribute = true, localName = "Severity")
    private String severity;
}
