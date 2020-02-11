package com.ptsecurity.appsec.ai.desktop.utils.report.generator.domain;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class GlossaryItem extends BaseDisplayName {
    @JacksonXmlProperty(isAttribute = true, localName = "TypeName")
    private String typeName;
    @JacksonXmlProperty(isAttribute = true, localName = "TypeId")
    private String typeId;
}
