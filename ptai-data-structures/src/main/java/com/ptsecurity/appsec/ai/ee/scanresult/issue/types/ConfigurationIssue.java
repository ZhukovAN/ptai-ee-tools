package com.ptsecurity.appsec.ai.ee.scanresult.issue.types;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
public class ConfigurationIssue extends BaseSourceIssue {
    /**
     * Code point with security misconfiguration
     */
    @JsonProperty("vulnerableExpression")
    protected Place vulnerableExpression;

    /**
     * Setting recommended value
     */
    @JsonProperty("recommendedValue")
    protected String recommendedValue;

    /**
     * Actual setting value
     */
    @JsonProperty("currentValue")
    protected String currentValue;
}
