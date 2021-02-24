package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Getter;
import lombok.ToString;

@Getter @ToString
public class ExcludedFilters extends IncludedFilters {
    @JacksonXmlProperty(isAttribute = true, localName = "SuspectedOrSecondOrder")
    protected String suspectedOrSecondOrder;
}
