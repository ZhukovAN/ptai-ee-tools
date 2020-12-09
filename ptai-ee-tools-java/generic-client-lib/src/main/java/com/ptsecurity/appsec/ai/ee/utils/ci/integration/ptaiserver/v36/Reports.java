package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.StringHelper;
import lombok.*;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.commons.text.similarity.CosineDistance;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.IssuesFilterExploitationCondition.ALL;

@Getter
@Setter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Reports {
    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    public enum Locale {
        EN("en-US"), RU("ru-RU");

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
        @Builder.Default
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
        @NoArgsConstructor(access = AccessLevel.PACKAGE)
        @RequiredArgsConstructor(access = AccessLevel.PACKAGE)
        public enum Format {
            XML(ReportFormatType.XML), JSON(ReportFormatType.JSON);

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
        @NonNull
        @JsonProperty
        protected String template;

        @NoArgsConstructor(access = AccessLevel.PACKAGE)
        @RequiredArgsConstructor(access = AccessLevel.PACKAGE)
        public enum Format {
            HTML(ReportFormatType.HTML),
            PDF(ReportFormatType.PDF);

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

    public Reports fix() {
        for (AbstractReport r : report) r.fix();
        for (AbstractReport r : data) r.fix();
        return this;
    }

    public Reports validate(@NonNull final Utils utils) {
        // Check if all the report file names are unique
        List<String> names = Stream.concat(report.stream(), data.stream())
                .map(AbstractReport::getFileName).collect(Collectors.toList());
        if (null != raw)
            names.addAll(raw.stream().map(RawData::getFileName).collect(Collectors.toList()));
        Map<String, Long> counters = names.stream()
                .collect(Collectors.groupingBy(n -> n, Collectors.counting()));
        List<String> duplicates = new ArrayList<>();
        for (String name : counters.keySet()) {
            if (1 < counters.get(name)) duplicates.add(name);
        }
        if (!duplicates.isEmpty()) {
            throw ApiException.raise(
                    "Duplicate output file names found",
                    new IllegalArgumentException("Duplicates are " + StringHelper.joinListGrammatically(duplicates)));
        }

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
        if (!missingTemplates.isEmpty()) {
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
        return this;
    }

    public static IssuesFilter verify(String json) throws ApiException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
            IssuesFilter res = mapper.readValue(json, IssuesFilter.class);
            return res;
        } catch (Exception e) {
            throw ApiException.raise("JSON settings parse failed", e);
        }
    }
}
