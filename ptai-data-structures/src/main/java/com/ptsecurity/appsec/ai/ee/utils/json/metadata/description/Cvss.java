package com.ptsecurity.appsec.ai.ee.utils.json.metadata.description;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Cvss {
    @JsonProperty("Base")
    protected String base;
    @JsonProperty("BaseScore")
    protected String baseScore;
    @JsonProperty("Temp")
    protected String temp;
    @JsonProperty("TempScore")
    protected String tempScore;
}
