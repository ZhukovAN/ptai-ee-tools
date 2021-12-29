package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

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
@AllArgsConstructor
public abstract class BaseSourceIssue extends BaseIssue {
    /**
     * Place in the file that defines file fragment
     * including name, line / column and contents
     */
    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Place {
        @NonNull
        @JsonProperty("beginLine")
        protected Integer beginLine;

        @NonNull
        @JsonProperty("beginColumn")
        protected Integer beginColumn;

        @NonNull
        @JsonProperty("endLine")
        protected Integer endLine;

        @NonNull
        @JsonProperty("endColumn")
        protected Integer endColumn;

        /**
         * File name
         */
        @NonNull
        @JsonProperty("file")
        protected String file;

        /**
         * File content that corresponds to this {@link Place}
         */
        @JsonProperty("value")
        protected String value;
    }

    /**
     * Unique vulnerability type identifier in the OWASP classifier
     */
    @JsonProperty("owaspId")
    protected List<String> owaspId;

    /**
     * Unique vulnerability type identifier in the PCI DSS classifier
     */
    @JsonProperty("pciDssId")
    protected List<String> pciDssId;

    /**
     * Unique vulnerability type identifier in the NIST classifier
     */
    @JsonProperty("nistId")
    protected List<String> nistId;
}
