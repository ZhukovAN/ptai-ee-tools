package com.ptsecurity.appsec.ai.ee.scanresult.issue.types;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.util.List;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
public class BlackBoxIssue extends BaseIssue {
    /**
     * Unique vulnerability type identifier in the OWASP classifier
     */
    @JsonProperty("OwaspId")
    protected List<String> owaspId;

    /**
     * Unique vulnerability type identifier in the PCI DSS classifier
     */
    @JsonProperty("PciDssId")
    protected List<String> pciDssId;

    /**
     * Unique vulnerability type identifier in the NIST classifier
     */
    @JsonProperty("NistId")
    protected List<String> nistId;
}
