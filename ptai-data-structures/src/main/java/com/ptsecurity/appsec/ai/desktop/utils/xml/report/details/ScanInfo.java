package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class ScanInfo {
    @JsonProperty("ScanSettings")
    protected ScanSettings scanSettings;
    @JsonProperty("FilterInformation")
    protected FilterInformation filterInformation;
}
