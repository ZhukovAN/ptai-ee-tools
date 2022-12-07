package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

import com.fasterxml.jackson.annotation.*;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.misc.tools.crypro.Hash;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.HashMap;
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
    public static Map<Class<? extends BaseIssue>, Type> TYPES = new HashMap<>();

    static {
        TYPES.put(UnknownIssue.class, Type.UNKNOWN);
        TYPES.put(BlackBoxIssue.class, Type.BLACKBOX);
        TYPES.put(ConfigurationIssue.class, Type.CONFIGURATION);
        TYPES.put(ScaIssue.class, Type.SCA);
        TYPES.put(WeaknessIssue.class, Type.WEAKNESS);
        TYPES.put(VulnerabilityIssue.class, Type.VULNERABILITY);
        TYPES.put(YaraMatchIssue.class, Type.YARAMATCH);
    }

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

    public enum Type {
        VULNERABILITY, WEAKNESS, SCA, CONFIGURATION, BLACKBOX, YARAMATCH, UNKNOWN
    }

    public static String getIssueTypeKey(@NonNull final BaseIssue issue) {
        return Hash.md5(issue.getClazz().name() + "::" + issue.getTypeId());
    }

    @Builder.Default
    private transient String issueTypeKey = null;

    @JsonProperty("issueTypeKey")
    public String getIssueTypeKey() {
        if (null == issueTypeKey) issueTypeKey = getIssueTypeKey(this);
        // return getIssueTypeKey(this);
        return issueTypeKey;
    }

    /**
     * Issue type: vulnerability, weakness, SCA, DAST etc.
     */
    @JsonIgnore
    public Type getClazz() {
        return TYPES.get(getClass());
    }

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

    @JsonProperty("isNew")
    protected Boolean isNew;

    /**
     * Unique vulnerability type identifier in the CWE classifier
     */
    @JsonProperty("cweId")
    protected List<String> cweId;
}
