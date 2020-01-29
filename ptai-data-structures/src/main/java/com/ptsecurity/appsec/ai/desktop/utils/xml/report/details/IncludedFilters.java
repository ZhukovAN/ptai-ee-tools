package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter @ToString
public class IncludedFilters {
    @JacksonXmlProperty(isAttribute = true, localName = "ConformationStatuses")
    protected String confirmationStatuses;
}
