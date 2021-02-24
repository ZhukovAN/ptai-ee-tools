package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.base.DisplayName;
import lombok.Getter;

@Getter
public class Type extends DisplayName {
    @JacksonXmlProperty(isAttribute = true, localName = "Id")
    protected String id;
    @JacksonXmlProperty(isAttribute = true, localName = "GroupId")
    protected String groupId;
}
