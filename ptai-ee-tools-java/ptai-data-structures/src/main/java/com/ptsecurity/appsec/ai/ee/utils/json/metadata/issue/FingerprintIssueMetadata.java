package com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.Cvss;

public class FingerprintIssueMetadata extends GenericIssueMetadata {
    @JsonProperty("Component")
    protected String component;
    @JsonProperty("CveId")
    protected String cveId;
    @JsonProperty("Cvss")
    protected Cvss cvss;
}
