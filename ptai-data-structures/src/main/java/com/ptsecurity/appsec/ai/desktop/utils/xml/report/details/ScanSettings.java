package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

@Getter
public class ScanSettings {
    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("Setting")
    protected List<Setting> setting = new ArrayList<>();
}
