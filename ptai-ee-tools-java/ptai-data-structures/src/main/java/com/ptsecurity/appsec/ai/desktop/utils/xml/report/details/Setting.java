package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.base.DisplayName;
import lombok.Getter;

@Getter
public class Setting extends DisplayName {
    @JacksonXmlProperty(isAttribute = true, localName = "Order")
    protected int order;
    @JacksonXmlProperty(isAttribute = true, localName = "IsExternalLink")
    protected boolean externalLink;
}
