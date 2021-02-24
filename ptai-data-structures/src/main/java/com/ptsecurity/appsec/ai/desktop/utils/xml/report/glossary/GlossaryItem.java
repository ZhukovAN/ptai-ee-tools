package com.ptsecurity.appsec.ai.desktop.utils.xml.report.glossary;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.base.DisplayName;
import lombok.Getter;

@Getter
public class GlossaryItem extends DisplayName {
    @JacksonXmlProperty(isAttribute = true, localName = "TypeName")
    protected String typeName;
    @JacksonXmlProperty(isAttribute = true, localName = "TypeId")
    protected String typeId;
}
