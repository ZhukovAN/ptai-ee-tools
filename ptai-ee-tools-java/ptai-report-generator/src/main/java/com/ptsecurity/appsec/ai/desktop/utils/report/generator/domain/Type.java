package com.ptsecurity.appsec.ai.desktop.utils.report.generator.domain;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class Type extends BaseDisplayName {
    @JacksonXmlProperty(isAttribute = true, localName = "Id")
    private String id;
    @JacksonXmlProperty(isAttribute = true, localName = "GroupId")
    private String groupId;
}
