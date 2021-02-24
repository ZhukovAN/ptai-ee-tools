package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.annotations.SerializedName;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.StringHelper;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.commons.text.similarity.CosineDistance;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.IssuesFilter.*;
import static org.apache.commons.lang3.ArrayUtils.isEmpty;

@Slf4j
@Getter
@Setter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Reports {
    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    public enum Locale {
        EN("en-US"), RU("ru-RU");

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
     *     Low       = 1 << 0,
     *     Medium    = 1 << 1,
     *     High      = 1 << 2,
     *     Potential = 1 << 3,
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
    public static class IssuesFilterEx {
        @SerializedName(SERIALIZED_NAME_ISSUE_LEVEL)
        private IssuesFilterLevel issueLevel;

        public static final String SERIALIZED_NAME_ISSUE_LEVELS = "issueLevels";
        @SerializedName(SERIALIZED_NAME_ISSUE_LEVELS)
        private IssuesFilterLevel[] issueLevels;

        @SerializedName(SERIALIZED_NAME_CONFIRMATION_STATUS)
        private IssuesFilterConfirmationStatus confirmationStatus;

        public static final String SERIALIZED_NAME_CONFIRMATION_STATUSES = "confirmationStatuses";
        @SerializedName(SERIALIZED_NAME_CONFIRMATION_STATUSES)
        private IssuesFilterConfirmationStatus[] confirmationStatuses;

        @SerializedName(SERIALIZED_NAME_EXPLOITATION_CONDITION)
        private IssuesFilterExploitationCondition exploitationCondition;

        public static final String SERIALIZED_NAME_EXPLOITATION_CONDITIONS = "exploitationConditions";
        @SerializedName(SERIALIZED_NAME_EXPLOITATION_CONDITIONS)
        private IssuesFilterExploitationCondition[] exploitationConditions;

        @SerializedName(SERIALIZED_NAME_SUPPRESS_STATUS)
        private IssuesFilterSuppressStatus suppressStatus;

        public static final String SERIALIZED_NAME_SUPPRESS_STATUSES = "suppressStatuses";
        @SerializedName(SERIALIZED_NAME_SUPPRESS_STATUSES)
        private IssuesFilterSuppressStatus[] suppressStatuses;

        @SerializedName(SERIALIZED_NAME_SOURCE_TYPE)
        private IssuesFilterSourceType sourceType;

        public static final String SERIALIZED_NAME_SOURCE_TYPES = "sourceTypes";
        @SerializedName(SERIALIZED_NAME_SOURCE_TYPES)
        private IssuesFilterSourceType[] sourceTypes;

        @SerializedName(SERIALIZED_NAME_SCAN_MODE)
        private IssuesFilterScanMode scanMode;

        public static final String SERIALIZED_NAME_SCAN_MODES = "scanModes";
        @SerializedName(SERIALIZED_NAME_SCAN_MODES)
        private IssuesFilterScanMode[] scanModes;

        public static final String SERIALIZED_NAME_ACTUAL_STATUS = "actualStatus";
        @SerializedName(SERIALIZED_NAME_ACTUAL_STATUS)
        private IssuesFilterActualStatus actualStatus;

        public static final String SERIALIZED_NAME_HIDE_SECOND_ORDER = "hideSecondOrder";
        @SerializedName(SERIALIZED_NAME_HIDE_SECOND_ORDER)
        private Boolean hideSecondOrder;

        public static final String SERIALIZED_NAME_HIDE_SUSPECTED = "hideSuspected";
        @SerializedName(SERIALIZED_NAME_HIDE_SUSPECTED)
        private Boolean hideSuspected;

        public static final String SERIALIZED_NAME_HIDE_POTENTIAL = "hidePotential";
        @SerializedName(SERIALIZED_NAME_HIDE_POTENTIAL)
        private Boolean hidePotential;

        public static final String SERIALIZED_NAME_BY_FAVORITE = "byFavorite";
        @SerializedName(SERIALIZED_NAME_BY_FAVORITE)
        private Boolean byFavorite;

        public static final String SERIALIZED_NAME_BY_BEST_PLACE_TO_FIX = "byBestPlaceToFix";
        @SerializedName(SERIALIZED_NAME_BY_BEST_PLACE_TO_FIX)
        private Boolean byBestPlaceToFix;

        public static final String SERIALIZED_NAME_TYPES = "types";
        @SerializedName(SERIALIZED_NAME_TYPES)
        private List<IssuesFilterType> types = null;

        public static final String SERIALIZED_NAME_PATH_INFO = "pathInfo";
        @SerializedName(SERIALIZED_NAME_PATH_INFO)
        private IssuesFilterPathInfo pathInfo;

        public static final String SERIALIZED_NAME_PATTERN = "pattern";
        @SerializedName(SERIALIZED_NAME_PATTERN)
        private String pattern;

        public static final String SERIALIZED_NAME_SELECT_ALL_LEVELS_SEPARATELY = "selectAllLevelsSeparately";
        @SerializedName(SERIALIZED_NAME_SELECT_ALL_LEVELS_SEPARATELY)
        private Boolean selectAllLevelsSeparately;

        public static final String SERIALIZED_NAME_SELECT_ALL_CONFIRMATION_STATUS_SEPARATELY = "selectAllConfirmationStatusSeparately";
        @SerializedName(SERIALIZED_NAME_SELECT_ALL_CONFIRMATION_STATUS_SEPARATELY)
        private Boolean selectAllConfirmationStatusSeparately;

        public static final String SERIALIZED_NAME_SELECT_ALL_EXPLOITATION_CONDITION_SEPARATELY = "selectAllExploitationConditionSeparately";
        @SerializedName(SERIALIZED_NAME_SELECT_ALL_EXPLOITATION_CONDITION_SEPARATELY)
        private Boolean selectAllExploitationConditionSeparately;

        public static final String SERIALIZED_NAME_SELECT_ALL_SUPPRESS_STATUS_SEPARATELY = "selectAllSuppressStatusSeparately";
        @SerializedName(SERIALIZED_NAME_SELECT_ALL_SUPPRESS_STATUS_SEPARATELY)
        private Boolean selectAllSuppressStatusSeparately;

        public static final String SERIALIZED_NAME_SELECT_ALL_SCAN_MODE_SEPARATELY = "selectAllScanModeSeparately";
        @SerializedName(SERIALIZED_NAME_SELECT_ALL_SCAN_MODE_SEPARATELY)
        private Boolean selectAllScanModeSeparately;

        public static final String SERIALIZED_NAME_SELECT_ALL_ACTUAL_STATUS_SEPARATELY = "selectAllActualStatusSeparately";
        @SerializedName(SERIALIZED_NAME_SELECT_ALL_ACTUAL_STATUS_SEPARATELY)
        private Boolean selectAllActualStatusSeparately;

        public IssuesFilter convert() {
            IssuesFilter res = new IssuesFilter();
            // No filters are defined - set ALL value
            if (null == issueLevel && isEmpty(issueLevels))
                res.setIssueLevel(IssuesFilterLevel.All.getValue());
            else {
                int rawValue = 0;
                if (null != issueLevel)
                    rawValue = issueLevel.getValue();
                if (ArrayUtils.isNotEmpty(issueLevels)) {
                    for (IssuesFilterLevel item : issueLevels)
                        rawValue |= item.getValue();
                }
                res.setIssueLevel(rawValue);
            }

            // No exploitation conditions are defined - set ALL value
            if (null == exploitationCondition && isEmpty(exploitationConditions))
                res.setExploitationCondition(IssuesFilterExploitationCondition.All.getValue());
            else {
                int rawValue = 0;
                if (null != exploitationCondition)
                    rawValue = exploitationCondition.getValue();
                if (ArrayUtils.isNotEmpty(exploitationConditions)) {
                    for (IssuesFilterExploitationCondition item : exploitationConditions)
                        rawValue |= item.getValue();
                }
                res.setExploitationCondition(rawValue);
            }

            // No scan modes are defined - set ALL value
            if (null == scanMode && isEmpty(scanModes))
                res.setScanMode(IssuesFilterScanMode.All.getValue());
            else {
                int rawValue = 0;
                if (null != scanMode)
                    rawValue = scanMode.getValue();
                if (ArrayUtils.isNotEmpty(scanModes)) {
                    for (IssuesFilterScanMode item : scanModes)
                        rawValue |= item.getValue();
                }
                res.setScanMode(rawValue);
            }

            // No suppress statuses are defined - set ALL value
            if (null == suppressStatus && isEmpty(suppressStatuses))
                res.setSuppressStatus(IssuesFilterSuppressStatus.All.getValue());
            else {
                int rawValue = 0;
                if (null != suppressStatus)
                    rawValue = suppressStatus.getValue();
                if (ArrayUtils.isNotEmpty(suppressStatuses)) {
                    for (IssuesFilterSuppressStatus item : suppressStatuses)
                        rawValue |= item.getValue();
                }
                res.setSuppressStatus(rawValue);
            }

            // No confirmation statuses are defined - set ALL value
            if (null == confirmationStatus && isEmpty(confirmationStatuses))
                res.setConfirmationStatus(IssuesFilterConfirmationStatus.All.getValue());
            else {
                int rawValue = 0;
                if (null != confirmationStatus)
                    rawValue = confirmationStatus.getValue();
                if (ArrayUtils.isNotEmpty(confirmationStatuses)) {
                    for (IssuesFilterConfirmationStatus item : confirmationStatuses)
                        rawValue |= item.getValue();
                }
                res.setConfirmationStatus(rawValue);
            }

            // No source types are defined - set ALL value
            if (null == sourceType && isEmpty(sourceTypes))
                res.setSourceType(IssuesFilterSourceType.All.getValue());
            else {
                int rawValue = 0;
                if (null != sourceType.getValue())
                    rawValue = sourceType.getValue();
                if (ArrayUtils.isNotEmpty(sourceTypes)) {
                    for (IssuesFilterSourceType item : sourceTypes)
                        rawValue |= item.getValue();
                }
                res.setSourceType(rawValue);
            }

            res.setActualStatus(null == actualStatus ? IssuesFilterActualStatus.ALL : actualStatus);

            res.setHideSecondOrder(null == hideSecondOrder ? false : hideSecondOrder);
            res.setHideSuspected(null == hideSuspected ? false : hideSuspected);
            res.setHidePotential(null == hidePotential ? false : hidePotential);

            res.setByFavorite(null == byFavorite ? false : byFavorite);
            res.setByBestPlaceToFix(null == byBestPlaceToFix ? false : byBestPlaceToFix);

            res.setTypes(types);
            res.setPattern(pattern);

            res.setSelectAllLevelsSeparately(null == selectAllLevelsSeparately ? false : selectAllLevelsSeparately);
            res.setSelectAllConfirmationStatusSeparately(null == selectAllConfirmationStatusSeparately ? false : selectAllConfirmationStatusSeparately);
            res.setSelectAllExploitationConditionSeparately(null == selectAllExploitationConditionSeparately ? false : selectAllExploitationConditionSeparately);
            res.setSelectAllSuppressStatusSeparately(null == selectAllSuppressStatusSeparately ? false : selectAllSuppressStatusSeparately);
            res.setSelectAllScanModeSeparately(null == selectAllScanModeSeparately ? false : selectAllScanModeSeparately);
            res.setSelectAllActualStatusSeparately(null == selectAllActualStatusSeparately ? false : selectAllActualStatusSeparately);

            return res;
        }
    }

    @Getter
    @Setter
    @JsonInclude(JsonInclude.Include.NON_NULL)
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
        protected IssuesFilterEx filters = null;

    }

    /**
     * Generic XML / JSON report that doesn't depend on template used
     */
    @Getter
    @Setter
    public static class Data extends AbstractReport {
        /**
         * Default report locale to be used for new data exports
         */
        public static final String DEFAULT_LOCALE = Locale.RU.name();

        /**
         * Default report format to be used for new data exports
         */
        public static final String DEFAULT_FORMAT = Format.JSON.name();

        @NoArgsConstructor(access = AccessLevel.PACKAGE)
        @RequiredArgsConstructor(access = AccessLevel.PACKAGE)
        public enum Format {
            XML(ReportFormatType.XML), JSON(ReportFormatType.JSON);

            private static final Map<String, Format> VALUES = new HashMap<>();

            static {
                for (Format f : values()) VALUES.put(f.value.getValue(), f);
            }

            public static Format from(@NonNull final String value) {
                return VALUES.get(value);
            }

            @Getter
            @NonNull
            @JsonProperty
            private ReportFormatType value;
        }

        @NonNull
        @JsonProperty
        public Format format;
    }


    @Getter
    @Setter
    public static class Report extends AbstractReport {

        /**
         * Default report locale to be used for new reports
         */
        public static final String DEFAULT_LOCALE = Locale.RU.name();

        /**
         * Default report format to be used for new reports
         */
        public static final String DEFAULT_FORMAT = Format.HTML.name();

        @NonNull
        @JsonProperty
        protected String template;

        @NoArgsConstructor(access = AccessLevel.PACKAGE)
        @RequiredArgsConstructor(access = AccessLevel.PACKAGE)
        public enum Format {
            HTML(ReportFormatType.HTML),
            PDF(ReportFormatType.PDF);

            private static final Map<String, Format> VALUES = new HashMap<>();

            static {
                for (Format f : values()) VALUES.put(f.value.getValue(), f);
            }

            public static Format from(@NonNull final String value) {
                return VALUES.get(value);
            }

            @Getter
            @NonNull
            @JsonProperty
            private ReportFormatType value;
        }

        @NonNull
        @JsonProperty
        public Format format;
    }

    @Getter
    @Setter
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
     * Raw JSON report from /api/Projects/{projectId}/scanResults/{scanResultId}/issues.
     * If null then no report will be generated
     */
    @JsonProperty
    protected List<RawData> raw = new ArrayList<>();

    public Reports check(@NonNull final Utils utils) {
        List<ImmutablePair<Locale, String>> missingTemplates = new ArrayList<>();
        // We will download all the templates for supported locales to give hint to user in case of typo
        List<ImmutablePair<Locale, String>> existingTemplates = new ArrayList<>();
        utils.fine("Checking report templates existence");
        for (Reports.Locale locale : Reports.Locale.values()) {
            // Get all templates for given locale
            List<String> templates = utils.getReportTemplates(locale).stream()
                    .map(ReportTemplateModel::getName)
                    .collect(Collectors.toList());
            for (String template : templates) existingTemplates.add(new ImmutablePair<>(locale, template));
            // Check if all the required report templates are present in list
            report.stream()
                    .filter(r -> locale.equals(r.locale))
                    .map(r -> r.template)
                    .forEach(t -> {
                        if (!templates.contains(t)) missingTemplates.add(new ImmutablePair<>(locale, t));
                    });
        }
        if (missingTemplates.isEmpty()) return this;

        // Let's give user a hint about most similar template names. To do that
        // we will calculate cosine distance between each of existing templates
        // and user value
        for (ImmutablePair<Locale, String> missing : missingTemplates) {
            List<Triple<Double, Locale, String>> distances = new ArrayList<>();
            for (ImmutablePair<Locale, String> existing : existingTemplates)
                distances.add(new ImmutableTriple<>(
                        new CosineDistance().apply(missing.right, existing.right), existing.left, existing.right));
            distances.sort(Comparator.comparing(Triple::getLeft));
            utils.info(
                    "No '%s' [%s] template name found. Most similar existing template is '%s' [%s] with %.1f%% similarity",
                    missing.right, missing.left, distances.get(0).getRight(), distances.get(0).getMiddle(),
                    100 - distances.get(0).getLeft() * 100);
        }
        throw ApiException.raise(
                "Not all report templates are exist on server",
                new IllegalArgumentException("Missing reports are " + StringHelper.joinListGrammatically(missingTemplates.stream().map(ImmutablePair::getRight).collect(Collectors.toList()))));
    }

    public static IssuesFilterEx validateJsonFilter(String json) throws ApiException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS);
            return mapper.readValue(json, IssuesFilterEx.class);
        } catch (Exception e) {
            throw ApiException.raise("JSON filter settings parse failed", e);
        }
    }

    /**
     * Method performs report settings validation."Validation" means that no PT AI server
     * interactions are performed at this stage. Reports checked against duplication of file names
     * @return "This" instance of reports being checked
     * @throws ApiException Exception that contains info about validation problems
     */
    public Reports validate() throws ApiException {
        // Check if all the report file names are unique
        List<String> names = Stream.concat(report.stream(), data.stream())
                .map(AbstractReport::getFileName).collect(Collectors.toList());
        if (null != raw)
            names.addAll(raw.stream().map(RawData::getFileName).collect(Collectors.toList()));
        // All file names are added to names list, let's count unique names
        Map<String, Long> counters = names.stream()
                .collect(Collectors.groupingBy(n -> n, Collectors.counting()));
        List<String> duplicates = new ArrayList<>();
        for (String name : counters.keySet())
            if (1 < counters.get(name)) duplicates.add(name);

        if (duplicates.isEmpty()) return this;

        throw ApiException.raise(
                "Duplicate output file names found",
                new IllegalArgumentException("Duplicates are " + StringHelper.joinListGrammatically(duplicates)));
    }

    /**
     * Method loads and validates reporting settings from JSON string
     * @param json String that contains JSON-defined reporting settings
     * @return Validated reports instance that corresponds JSON data
     * @throws ApiException Exception that contains error info if
     * JSON load / parse / validation was failed
     */
    public static Reports validateJsonReports(final String json) throws ApiException {
        return load(json).validate();
    }

    /**
     * Method loads JSON-defined reporting settings from string
     * @param json String that contains JSON-defined reporting settings
     * @return Reports instance that corresponds JSON data
     * @throws ApiException Exception that contains error info if JSON load / parse was failed
     */
    public static Reports load(String json) throws ApiException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS);
            return mapper.readValue(json, Reports.class);
        } catch (Exception e) {
            throw ApiException.raise(Resources.i18n_ast_result_reporting_json_message_file_parse_failed(), e);
        }
    }

    public Reports append(@NonNull final Reports reports) {
        getReport().addAll(reports.getReport());
        getData().addAll(reports.getData());
        getRaw().addAll(reports.getRaw());
        return this;
    }
}
