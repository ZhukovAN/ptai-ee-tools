package com.ptsecurity.appsec.ai.ee.scan.reports;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Set of reports to be generated after AST job is complete
 */
@Slf4j
@Getter
@Setter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
public class Reports {
    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    @ToString
    public enum Locale {
        EN("en-US", 1033, java.util.Locale.US),

        RU("ru-RU", 1049, new java.util.Locale("ru", "RU"));

        private static final Map<String, Locale> VALUES = new HashMap<>();

        static {
            for (Locale f : values()) VALUES.put(f.value, f);
        }

        public static Locale from(@NonNull final String value) {
            return VALUES.get(value);
        }

        @Getter
        @NonNull
        private final String value;

        @Getter
        private final int code;

        @Getter
        @NonNull
        private final java.util.Locale locale;
    }

    /**
     * PT AI project management API supports reports generation that
     * allows using IssuesFilter parameters like issuesLevel,
     * confirmationStatus, scanMode etc. But those fields are defined in
     * Swagger API descriptions as single enums, not as arrays. That means
     * that you can't generate report that contain only vulnerabilities of
     * high and medium levels, you may define only one value: high or
     * medium. But internal implementation of PT AI report generation API
     * uses bit masks to support multiple fields definition.
     * For example, issues levels are defined as follows:
     *     None      = 0,
     *     Low       = 1 shl 0,
     *     Medium    = 1 shl 1,
     *     High      = 1 shl 2,
     *     Potential = 1 shl 3,
     *     All       = Low | Medium | High | Potential
     * That means that it is possible to define more than one field value to
     * solve task described above. To do that I've changed Swagger API definition
     * for IssuesFilter type: corresponding fields now defined as integers,
     * not enums. But for user convenience we need to let him define JSONs using
     * old-fashioned enum values. This class implements those values as both
     * single- and multi-valued attributes and provides method to convert it
     * to IssuesFilter
     */
    @Getter
    @Setter
    @ToString
    public static class IssuesFilter {
        /**
         * The same set of vulnerability levels as defined in
         * {@link com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue.Level} plus ALL
         */
        public enum Level {
            NONE, LOW, MEDIUM, HIGH, POTENTIAL, ALL
        }
        @JsonProperty("issueLevel")
        private Level issueLevel;

        @JsonProperty("issueLevels")
        private Level[] issueLevels;

        public enum ApprovalState {
            UNDEFINED, NONE, APPROVED, AUTOAPPROVED, DISCARDED, ALL
        }

        @JsonProperty("confirmationStatus")
        private ApprovalState confirmationStatus;

        @JsonProperty("confirmationStatuses")
        private ApprovalState[] confirmationStatuses;

        public enum Condition {
            NONE, NOCONDITION, UNDERCONDITION, ALL
        }
        @JsonProperty("exploitationCondition")
        private Condition exploitationCondition;

        @JsonProperty("exploitationConditions")
        private Condition[] exploitationConditions;

        public enum SuppressStatus {
            NONE, SUPPRESSED, EXCEPTSUPPRESSED, ALL
        }
        @JsonProperty("suppressStatus")
        private SuppressStatus suppressStatus;

        @JsonProperty("suppressStatuses")
        private SuppressStatus[] suppressStatuses;

        public enum SourceType {
            NONE, STATIC, BLACKBOX, ALL
        }

        @JsonProperty("sourceType")
        private SourceType sourceType;

        @JsonProperty("sourceTypes")
        private SourceType[] sourceTypes;

        public enum ScanMode {
            NONE, FROMENTRYPOINT, FROMPUBLICPROTECTED, FROMOTHER, ALL
        }
        @JsonProperty("scanMode")
        private ScanMode scanMode;

        @JsonProperty("scanModes")
        private ScanMode[] scanModes;

        public enum ActualStatus {
            ISNEW, NOTISNEW, ALL
        }

        @JsonProperty("actualStatus")
        private ActualStatus actualStatus;

        @JsonProperty("hideSecondOrder")
        private Boolean hideSecondOrder;

        @JsonProperty("hideSuspected")
        private Boolean hideSuspected;

        @JsonProperty("hidePotential")
        private Boolean hidePotential;

        @JsonProperty("byFavorite")
        private Boolean byFavorite;

        @JsonProperty("byBestPlaceToFix")
        private Boolean byBestPlaceToFix;

        @JsonProperty("types")
        private List<String> types = new ArrayList<>();

        @Getter
        @Setter
        @NoArgsConstructor
        @ToString
        public static class PathInfo {
            @JsonProperty("path")
            private String path;

            @JsonProperty("physicalPath")
            private String physicalPath;
        }

        @JsonProperty("pathInfo")
        private PathInfo pathInfo;

        @JsonProperty("pattern")
        private String pattern;

        @JsonProperty("selectAllLevelsSeparately")
        private Boolean selectAllLevelsSeparately;

        @JsonProperty("selectAllConfirmationStatusSeparately")
        private Boolean selectAllConfirmationStatusSeparately;

        @JsonProperty("selectAllExploitationConditionSeparately")
        private Boolean selectAllExploitationConditionSeparately;

        @JsonProperty("selectAllSuppressStatusSeparately")
        private Boolean selectAllSuppressStatusSeparately;

        @JsonProperty("selectAllScanModeSeparately")
        private Boolean selectAllScanModeSeparately;

        @JsonProperty("selectAllActualStatusSeparately")
        private Boolean selectAllActualStatusSeparately;
    }

    @Getter
    @Setter
    @SuperBuilder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @NoArgsConstructor
    @ToString
    public static abstract class AbstractReport {
        /**
         * File name where report should be saved to
         */
        @NonNull
        @JsonProperty
        public String fileName;

        /**
         * Report locale
         */
        @NonNull
        @JsonProperty
        public Locale locale;

        /**
         * Report property that contain report generation filters
         */
        @JsonProperty
        @Builder.Default
        protected IssuesFilter filters = null;
    }

    /**
     * Generic XML / JSON report that doesn't depend on template used
     */
    @Getter
    @Setter
    @ToString(callSuper = true)
    @SuperBuilder
    @NoArgsConstructor
    public static class Data extends AbstractReport {
        /**
         * Default report locale to be used for new data exports
         */
        public static final String DEFAULT_LOCALE = Locale.RU.name();

        /**
         * Default report format to be used for new data exports
         */
        public static final String DEFAULT_FORMAT = Format.JSON.name();

        public enum Format {
            JSON, XML
        }

        @NonNull
        @JsonProperty
        public Format format;
    }


    @Getter
    @Setter
    @ToString(callSuper = true)
    @SuperBuilder
    @NoArgsConstructor
    public static class Report extends AbstractReport {

        /**
         * Default report locale to be used for new reports
         */
        public static final String DEFAULT_LOCALE = Locale.RU.name();

        /**
         * Default report format to be used for new reports
         */
        public static final String DEFAULT_FORMAT = Format.HTML.name();

        public static Map<Locale, String> DEFAULT_TEMPLATE_NAME = new HashMap<>();

        static {
            DEFAULT_TEMPLATE_NAME.put(Locale.EN, "Scan results report");
            DEFAULT_TEMPLATE_NAME.put(Locale.RU, "Отчет по результатам сканирования");
        }

        @NonNull
        @JsonProperty
        protected String template;

        public enum Format {
            HTML, PDF
        }

        @NonNull
        @JsonProperty
        public Format format;
    }

    @Getter
    @Setter
    @ToString
    @NoArgsConstructor
    @SuperBuilder
    public static class RawData {
        /**
         * File name where report should be saved to
         */
        @NonNull
        @JsonProperty
        public String fileName;
    }

    /**
     * List of human-readable reports to be generated. Such report type
     * generation requires template name, output format (HTML or PDF),
     * output file name and filters
     */
    @NonNull
    @JsonProperty
    protected List<Report> report = new ArrayList<>();
    /**
     * List of machine-readable reports to be generated. Such report type
     * differ from human-readable as they do not require template name
     */
    @NonNull
    @JsonProperty
    protected List<Data> data = new ArrayList<>();

    /**
     * Raw JSON report that is result of conversion from /api/Projects/{projectId}/scanResults/{scanResultId}/issues
     * call result to PT ai version-independent {@link com.ptsecurity.appsec.ai.ee.scan.result.ScanResult}.
     * If null then no report will be generated
     */
    @JsonProperty
    protected List<RawData> raw = new ArrayList<>();

    /**
     * Builder-like method that adds reports and returns "this" instance
     * @param reports Reports to be added
     * @return Reports instance with new items added
     */
    public Reports append(@NonNull final Reports reports) {
        getReport().addAll(reports.getReport());
        getData().addAll(reports.getData());
        getRaw().addAll(reports.getRaw());
        return this;
    }
}
