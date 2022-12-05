package com.ptsecurity.appsec.ai.ee.scan.result;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Class that stores top-level information about completed AST job. That
 * information includes AST settings, policy assessment result and very
 * short statistic about scan duration, number of scanned / skipped
 * files / urls etc. This class have two descendants: ScanBriefDetailed
 * and even more detailed ScanResult
 */
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class ScanBrief {
    public enum ApiVersion {
        V411, V42
    }

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    @Builder.Default
    protected ApiVersion apiVersion = ApiVersion.V42;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected String ptaiServerUrl;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected String ptaiServerVersion;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected String ptaiAgentVersion;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected UUID id;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected UUID projectId;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected String projectName;

    @Getter
    @Setter
    @JsonProperty
    @Builder.Default
    protected Boolean useAsyncScan = false;

    @Getter
    @Setter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ScanSettings {
        @NonNull
        @JsonProperty
        protected UUID id;

        public enum Engine {
            AI, PM, TAINT, DC, FINGERPRINT, CONFIGURATION, BLACKBOX
        }

        @Builder.Default
        @JsonProperty
        protected final Set<Engine> engines = new HashSet<>();

        @JsonProperty
        protected Boolean unpackUserPackages;

        @JsonProperty
        protected Boolean downloadDependencies;

        @JsonProperty
        protected Boolean usePublicAnalysisMethod;

        @JsonProperty
        protected Boolean useEntryAnalysisPoint;

        @RequiredArgsConstructor
        public enum Language {
            PHP("PHP"),
            JAVA("Java"),
            CSHARP("CSharp"),
            VB("VB"),
            JAVASCRIPT("JavaScript"),
            GO("Go"),
            CPP("CPlusPlus"),
            PYTHON("Python"),
            SQL("SQL"),
            OBJECTIVEC("ObjectiveC"),
            SWIFT("Swift"), KOTLIN("Kotlin");

            public static Language fromString(@NonNull final String value) {
                for (Language language : Language.values())
                    if (language.value.equalsIgnoreCase(value)) return language;
                throw new IllegalArgumentException("No enum value " + Language.class.getCanonicalName() + "." + value);
            }

            @NonNull
            private final String value;
        }

        @JsonProperty
        protected Language language;

        @JsonProperty
        protected String url;

        @JsonProperty
        protected Boolean autocheckAfterScan;

        @JsonProperty
        protected String customParameters;

        @JsonProperty
        protected String javaParameters;
    }

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected ScanSettings scanSettings;

    @Getter
    @Setter
    @NonNull
    @Builder.Default
    @JsonProperty
    protected Policy.State policyState = Policy.State.NONE;

    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    @AllArgsConstructor
    @ToString
    public static class Statistics {
        /**
         * Scan execution date / time. Can't use Java 8 ZonedDateTime, Instant etc. as Jenkins
         * complaints "Refusing to marshal java.time.Instant for security reasons;
         * see https://jenkins.io/redirect/class-filter/"
         */
        @NonNull
        @JsonProperty
        protected String scanDateIso8601;

        @NonNull
        @JsonProperty
        protected String scanDurationIso8601;

        protected int totalFileCount;
        protected int totalUrlCount;
        protected int scannedFileCount;
        protected int scannedUrlCount;
    }

    @Getter
    @Setter
    protected Statistics statistics;

    public enum State {
        UNKNOWN, DONE, FAILED, ABORTED
    }

    @Getter
    @Setter
    @NonNull
    @Builder.Default
    protected ScanBrief.State state = ScanBrief.State.UNKNOWN;
}