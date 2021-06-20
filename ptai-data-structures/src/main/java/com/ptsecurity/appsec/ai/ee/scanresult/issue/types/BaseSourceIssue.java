package com.ptsecurity.appsec.ai.ee.scanresult.issue.types;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.List;

/**
 * Class that defines vulnerability found in the source file
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
public abstract class BaseSourceIssue extends BaseIssue {
    /**
     * Place in the file that defines file fragment
     * including name, line / column and contents
     */
    @Getter
    @Setter
    @Builder
    public static class Place {
        @NonNull
        @JsonProperty("BeginLine")
        protected Integer beginLine;

        @NonNull
        @JsonProperty("BeginColumn")
        protected Integer beginColumn;

        @NonNull
        @JsonProperty("EndLine")
        protected Integer endLine;

        @NonNull
        @JsonProperty("EndColumn")
        protected Integer endColumn;

        /**
         * File name
         */
        @NonNull
        @JsonProperty("File")
        protected String file;

        /**
         * File content that corresponds to this {@link Place}
         */
        @JsonProperty("Value")
        protected String value;
    }

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
