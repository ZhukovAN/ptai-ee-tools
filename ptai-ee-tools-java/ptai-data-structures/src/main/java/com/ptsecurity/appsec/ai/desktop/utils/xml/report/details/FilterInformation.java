package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.ToString;

@Getter @ToString
public class FilterInformation {
    @JsonProperty("IncludedFilters")
    protected IncludedFilters includedFilters;
    @JsonProperty("ExcludedFilters")
    protected ExcludedFilters excludedFilters;
}
