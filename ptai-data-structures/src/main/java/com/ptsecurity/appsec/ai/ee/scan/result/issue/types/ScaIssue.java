package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
public class ScaIssue extends BaseIssue {
    /**
     * Vulnerable file
     */
    @JsonProperty("file")
    protected String file;

    /**
     * Vulnerable component name
     */
    @JsonProperty("componentName")
    protected String componentName;

    /**
     * Vulnerable component version
     */
    @JsonProperty("componentVersion")
    protected String componentVersion;

    /**
     * Fingerprints that is immanent to this vulnerability
     */
    @JsonProperty("fingerprintId")
    protected String fingerprintId;

    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    public static class Cvss {
        @JsonProperty("base")
        protected String base;
        @JsonProperty("baseScore")
        protected String baseScore;
        @JsonProperty("temp")
        protected String temp;
        @JsonProperty("tempScore")
        protected String tempScore;
    }

    /**
     * Unique vulnerability type identifier in the CVE classifier like CVE-2012-6708
     */
    @JsonProperty("cveId")
    protected String cveId;

    /**
     * CVSS score assigned to  this vulnerability
     */
    @JsonProperty("cvss")
    protected Cvss cvss;
}
