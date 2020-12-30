package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.StringHelper;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.commons.text.similarity.CosineDistance;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.IssuesFilterExploitationCondition.ALL;

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
        protected IssuesFilter filters = null;

        /**
         * All the filters that use enum values are treated as NONE if no value
         * is defined in JSON. But this is not convenient for user as he thinks that if
         * no filter is defined then filtering must not be done on that field. So we need
         * to fix all the missing filters with ALL enum
         *
         * @return Fixed NamedReportDefinition where all missing fields are filled with "ALL" value
         */
        public AbstractReport fix() {
            if (null == filters) return this;

            if (null == filters.getIssueLevel())
                filters.setIssueLevel(IssuesFilterLevel.ALL);
            if (null == filters.getExploitationCondition())
                filters.setExploitationCondition(ALL);
            if (null == filters.getScanMode())
                filters.setScanMode(IssuesFilterScanMode.ALL);
            if (null == filters.getSuppressStatus())
                filters.setSuppressStatus(IssuesFilterSuppressStatus.ALL);
            if (null == filters.getConfirmationStatus())
                filters.setConfirmationStatus(IssuesFilterConfirmationStatus.ALL);
            if (null == filters.getSourceType())
                filters.setSourceType(IssuesFilterSourceType.ALL);

            return this;
        }
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

    /**
     * See {@link AbstractReport#fix()}
     * @return "This" reports instance with fixed report items
     */
    public Reports fix() {
        for (AbstractReport r : report) r.fix();
        for (AbstractReport r : data) r.fix();
        return this;
    }

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

    public static IssuesFilter validateJsonFilter(String json) throws ApiException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            IssuesFilter res = mapper.readValue(json, IssuesFilter.class);
            return res;
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
            Reports res = mapper.readValue(json, Reports.class);
            return res.fix();
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
