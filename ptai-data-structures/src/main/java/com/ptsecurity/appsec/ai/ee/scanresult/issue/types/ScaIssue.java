package com.ptsecurity.appsec.ai.ee.scanresult.issue.types;

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
    @AllArgsConstructor
    @Builder
    public static class Cvss {
        @JsonProperty("Base")
        protected String base;
        @JsonProperty("BaseScore")
        protected String baseScore;
        @JsonProperty("Temp")
        protected String temp;
        @JsonProperty("TempScore")
        protected String tempScore;
    }

    /**
     * Unique vulnerability type identifier in the CVE classifier like CVE-2012-6708
     */
    @JsonProperty("CveId")
    protected String cveId;

    /**
     * CVSS score assigned to  this vulnerability
     */
    @JsonProperty("Cvss")
    protected Cvss cvss;
}
