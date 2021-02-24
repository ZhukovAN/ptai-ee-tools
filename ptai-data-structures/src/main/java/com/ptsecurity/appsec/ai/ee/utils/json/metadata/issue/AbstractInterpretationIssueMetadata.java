package com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AbstractInterpretationIssueMetadata extends GenericIssueMetadata {
    @JsonProperty("OwaspId")
    protected String OwaspId;
    @JsonProperty("PciId")
    protected String pciId;
    @JsonProperty("Nist")
    protected String nist;
}
