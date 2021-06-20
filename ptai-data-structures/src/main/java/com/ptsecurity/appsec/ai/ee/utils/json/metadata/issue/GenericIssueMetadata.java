package com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Getter;

@Deprecated
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "IssueType")
@JsonSubTypes({
        @JsonSubTypes.Type(value = AbstractInterpretationIssueMetadata.class, name = "1"),
        @JsonSubTypes.Type(value = PatternMatchingIssueMetadata.class, name = "2"),
        @JsonSubTypes.Type(value = FingerprintIssueMetadata.class, name = "4"),
        @JsonSubTypes.Type(value = ConfigurationIssueMetadata.class, name = "3")
})
@Getter
public abstract class GenericIssueMetadata {
    @JsonProperty("CweId")
    protected String cweId;
    @JsonProperty("Key")
    protected String key;
    @JsonProperty("Level")
    protected Integer level;
}
