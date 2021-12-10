package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.GenericAstTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ScanResultHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;

@Slf4j
@Getter
@Setter
@SuperBuilder
@RequiredArgsConstructor
@ToString
public class SonarGiif extends Export {
    /**
     * https://docs.sonarqube.org/latest/analysis/generic-issue/
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Getter
    @Setter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SonarGiifReport {
        @JsonProperty
        @Builder.Default
        @NonNull
        protected List<Issue> issues = new ArrayList<>();

        @JsonInclude(JsonInclude.Include.NON_NULL)
        @Getter
        @Setter
        @Builder
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Issue {
            @JsonProperty
            @NonNull
            protected String engineId;

            @JsonProperty
            @NonNull
            protected String ruleId;

            /**
             * One of BUG, VULNERABILITY, CODE_SMELL
             */
            public enum Type {
                BUG, VULNERABILITY, CODE_SMELL
            }

            @JsonProperty
            @NonNull
            protected Type type;

            /**
             * One of BLOCKER, CRITICAL, MAJOR, MINOR, INFO
             */
            public enum Severity {
                BLOCKER, CRITICAL, MAJOR, MINOR, INFO
            }

            @JsonProperty
            @NonNull
            protected Severity severity;

            /**
             * Integer, optional. Defaults to 0
             */
            @JsonProperty
            @Builder.Default
            protected Integer effortMinutes = null;

            @JsonInclude(JsonInclude.Include.NON_NULL)
            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
            @AllArgsConstructor
            public static abstract class Location {
                @JsonProperty
                @NonNull
                protected String message;

                @JsonProperty
                @NonNull
                protected String filePath;

                @JsonInclude(JsonInclude.Include.NON_NULL)
                @Getter
                @Setter
                @Builder
                @NoArgsConstructor
                @AllArgsConstructor
                public static class TextRange {
                    /**
                     * 1-indexed
                     */
                    @JsonProperty
                    @Builder.Default
                    @NonNull
                    protected Integer startLine = 1;
                    /**
                     * Optional. 1-indexed
                     */
                    @JsonProperty
                    @Builder.Default
                    protected Integer endLine = null;
                    /**
                     * Optional. 0-indexed
                     */
                    @JsonProperty
                    @Builder.Default
                    protected Integer startColumn = null;
                    /**
                     * Optional. 0-indexed
                     */
                    @JsonProperty
                    @Builder.Default
                    protected Integer endColumn = null;
                }
            }

            @JsonInclude(JsonInclude.Include.NON_NULL)
            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
            @AllArgsConstructor
            public static class PrimaryLocation extends Location {
                @JsonProperty
                @Builder.Default
                @NonNull
                protected TextRange textRange = new TextRange();
            }

            @JsonInclude(JsonInclude.Include.NON_NULL)
            @Getter
            @Setter
            @SuperBuilder
            @NoArgsConstructor
            @AllArgsConstructor
            public static class SecondaryLocation extends Location {
                @JsonProperty
                @Builder.Default
                protected TextRange textRange = null;
            }

            @JsonProperty
            @NonNull
            protected PrimaryLocation primaryLocation;

            @JsonProperty
            @Builder.Default
            protected List<SecondaryLocation> secondaryLocations = null;
        }

    }
    @NonNull
    protected final Reports.SonarGiif sonar;

    @Override
    public void validate() throws GenericException {
        ReportsTasks reportsTasks = new Factory().reportsTasks(owner.getClient());
        reportsTasks.check(sonar);
    }

    @Override
    public void execute(@NonNull ScanBrief scanBrief) throws GenericException {
        GenericAstTasks genericAstTasks = new Factory().genericAstTasks(owner.getClient());
        ScanResult scanResult = genericAstTasks.getScanResult(scanBrief.getProjectId(), scanBrief.getId());
        ScanResultHelper.apply(scanResult, sonar.getFilters());

        SonarGiifReport sonarGiif = convert(scanResult);
        String sarifStr = CallHelper.call(
                () -> BaseJsonHelper.createObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(sonarGiif),
                "SARIF report serialization failed");
        owner.getFileOps().saveArtifact(this.sonar.getFileName(), sarifStr.getBytes(StandardCharsets.UTF_8));
    }

    private static final Map<BaseIssue.Level, SonarGiifReport.Issue.Severity> ISSUE_LEVEL_MAP = new HashMap<>();
    private static final Map<BaseIssue.Level, SonarGiifReport.Issue.Type> ISSUE_TYPE_MAP = new HashMap<>();

    static {
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.NONE, SonarGiifReport.Issue.Severity.INFO);
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.POTENTIAL, SonarGiifReport.Issue.Severity.INFO);
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.LOW, SonarGiifReport.Issue.Severity.MINOR);
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.MEDIUM, SonarGiifReport.Issue.Severity.MAJOR);
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.HIGH, SonarGiifReport.Issue.Severity.CRITICAL);

        ISSUE_TYPE_MAP.put(BaseIssue.Level.NONE, SonarGiifReport.Issue.Type.CODE_SMELL);
        ISSUE_TYPE_MAP.put(BaseIssue.Level.POTENTIAL, SonarGiifReport.Issue.Type.VULNERABILITY);
        ISSUE_TYPE_MAP.put(BaseIssue.Level.LOW, SonarGiifReport.Issue.Type.VULNERABILITY);
        ISSUE_TYPE_MAP.put(BaseIssue.Level.MEDIUM, SonarGiifReport.Issue.Type.VULNERABILITY);
        ISSUE_TYPE_MAP.put(BaseIssue.Level.HIGH, SonarGiifReport.Issue.Type.VULNERABILITY);

    }

    @SneakyThrows
    @NonNull
    public static SonarGiifReport convert(@NonNull final ScanResult scanResult) {
        SonarGiifReport result = SonarGiifReport.builder().build();

        for (BaseIssue issue : scanResult.getIssues()) {
            String message = scanResult.getI18n().get(issue.getTypeId()).get(EN).getTitle();
            SonarGiifReport.Issue.PrimaryLocation primaryLocation;
            BaseIssue.Type clazz = issue.getClazz();
            if (BaseIssue.Type.SCA == clazz) {
                ScaIssue scaIssue = (ScaIssue) issue;
                // Set SCA issue location. That location is file-scope only and
                // doesn't contain line and column numbers
                primaryLocation = SonarGiifReport.Issue.PrimaryLocation.builder()
                        .filePath(fixUri(scaIssue.getFile()))
                        .message(message)
                        .build();
            } else if (BaseIssue.Type.CONFIGURATION == clazz) {
                ConfigurationIssue configurationIssue = (ConfigurationIssue) issue;
                primaryLocation = pl(message, configurationIssue.getVulnerableExpression());
            } else if (BaseIssue.Type.VULNERABILITY == clazz) {
                VulnerabilityIssue vulnerabilityIssue = (VulnerabilityIssue) issue;
                primaryLocation = pl(message, vulnerabilityIssue.getVulnerableExpression());
            } else if (BaseIssue.Type.WEAKNESS == clazz) {
                WeaknessIssue weaknessIssue = (WeaknessIssue) issue;
                primaryLocation = pl(message, weaknessIssue.getVulnerableExpression());
            } else continue;
            result.getIssues().add(SonarGiifReport.Issue.builder()
                    .engineId("PTAI")
                    .ruleId(issue.getTypeId())
                    .severity(ISSUE_LEVEL_MAP.get(issue.getLevel()))
                    .type(ISSUE_TYPE_MAP.get(issue.getLevel()))
                    .primaryLocation(primaryLocation)
                    .build());
        }
        return result;
    }

    public static String fixUri(@NonNull final String uri) {
        return StringUtils.removeStart(uri, ".\\").replaceAll("\\\\", "/");
    }

    public static SonarGiifReport.Issue.Location.TextRange textRange(@NonNull final BaseSourceIssue.Place place) {
        SonarGiifReport.Issue.Location.TextRange result = new SonarGiifReport.Issue.Location.TextRange();

        if (place.getBeginLine() > 0) result.setStartLine(place.getBeginLine());
        if (place.getEndLine() > 0 && place.getEndLine() > place.getBeginLine()) result.setEndLine(place.getEndLine());

        if (!place.getBeginColumn().equals(place.getEndColumn())) {
            if (place.getBeginColumn() > 0) result.setStartColumn(place.getBeginColumn());
            if (place.getEndColumn() > 0 && place.getEndColumn() > place.getBeginColumn()) result.setEndColumn(place.getEndColumn());
        }

        return result;
    }

    public static SonarGiifReport.Issue.PrimaryLocation pl(@NonNull final String message, @NonNull final BaseSourceIssue.Place place) {
        SonarGiifReport.Issue.Location.TextRange textRange = textRange(place);
        return SonarGiifReport.Issue.PrimaryLocation.builder()
                .textRange(textRange).message(message).filePath(fixUri(place.getFile())).build();
    }

}
