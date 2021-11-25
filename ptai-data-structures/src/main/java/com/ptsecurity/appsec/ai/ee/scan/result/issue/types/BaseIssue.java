package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

import com.fasterxml.jackson.annotation.*;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Common base parent class for all issues. As it is base it does
 * contain only fields that are not specific
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "class")
@JsonSubTypes({
        @JsonSubTypes.Type(value = BlackBoxIssue.class, name = "BLACKBOX"),
        @JsonSubTypes.Type(value = ConfigurationIssue.class, name = "CONFIGURATION"),
        @JsonSubTypes.Type(value = ScaIssue.class, name = "SCA"),
        @JsonSubTypes.Type(value = UnknownIssue.class, name = "UNKNOWN"),
        @JsonSubTypes.Type(value = VulnerabilityIssue.class, name = "VULNERABILITY"),
        @JsonSubTypes.Type(value = WeaknessIssue.class, name = "WEAKNESS"),
        @JsonSubTypes.Type(value = YaraMatchIssue.class, name = "YARAMATCH")
})
public abstract class BaseIssue {
    /**
     * Unique issue identifier
     */
    @JsonProperty("id")
    protected String id;

    /**
     * Issue group identifier. Null if issue doesn't belong to group
     */
    @JsonProperty("groupId")
    protected String groupId;

    /**
     * Unique issue type identifier
     */
    @JsonProperty("typeId")
    protected String typeId;

    /**
     * Scan result this issue belongs to
     * TODO: Chek if we may get rid of this
     */
    @NonNull
    @JsonProperty("scanResultId")
    protected UUID scanResultId;

    public enum Type {
        VULNERABILITY, WEAKNESS, SCA, CONFIGURATION, BLACKBOX, YARAMATCH, UNKNOWN
    }

    /**
     * Issue type: vulnerability, weakness, SCA, DAST etc.
     */
    // @JsonProperty("class")
    @JsonIgnore
    protected Type clazz;

    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    public enum Level {
        NONE(0),
        POTENTIAL(1),
        LOW(2),
        MEDIUM(3),
        HIGH(4);

        @Getter
        private final int value;
    }

    /**
     * Issue severity level
     */
    @JsonProperty("level")
    protected Level level;

    /**
     * True if issue marked as favorite in UI
     */
    @JsonProperty("isFavorite")
    protected Boolean favorite;

    /**
     * True if issue is a suspected vulnerability i.e. PT AI not
     * sure if it can be exploited
     */
    @JsonProperty("isSuspected")
    protected Boolean suspected;

    /**
     * True if issue marked with suppress comment in source code
     */
    @JsonProperty("isSuppressed")
    protected Boolean suppressed;

    /**
     * Issue approval state. This state persisted between scans: if vulnerability
     * was marked as approved after last scan but developer haven't fixed it then
     * approval state will be automatically assigned to issue in a new scan results
     */
    public enum ApprovalState {
        /**
         * No approval state defined
         */
        NONE,
        /**
         * Issue approved
         */
        APPROVAL,
        /**
         * Issue declined
         */
        DISCARD,
        NOT_EXIST,
        /**
         * Issue approved during auto-check stage
         */
        AUTO_APPROVAL
    }

    /**
     * Issue approval state @see IssueApprovalState
     */
    @JsonProperty("approvalState")
    protected ApprovalState approvalState;

    @JsonProperty("newInScanResultId")
    protected UUID newInScanResultId;

    @JsonProperty("oldInScanResultId")
    protected UUID oldInScanResultId;

    /**
     * Unique vulnerability type identifier in the CWE classifier
     */
    @JsonProperty("cweId")
    protected List<String> cweId;
}
