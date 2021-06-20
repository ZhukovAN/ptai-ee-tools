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
public class WeaknessIssue extends BaseSourceIssue {
    /**
     * Code point that pattern has matched. Value field contains matching code fragment
     */
    @JsonProperty("vulnerableExpression")
    protected Place vulnerableExpression;
}
