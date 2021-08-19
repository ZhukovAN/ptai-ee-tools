package com.ptsecurity.appsec.ai.ee.scan.result;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.*;

/**
 * Class that stores top-level information about completed AST job. That
 * information includes AST settings, policy assessment result and very
 * short statistic about scan duration, number of scanned / skipped
 * files / urls etc. This class have two descendants: ScanBriefDetailed
 * and even more detailed ScanResult
 */
@SuperBuilder
@NoArgsConstructor
public class ScanBrief {
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
    @SuperBuilder
    @NoArgsConstructor
    public static class ScanSettings {
        @NonNull
        @JsonProperty
        protected UUID id;

        public static enum Engine {
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

        public enum Language {
            PHP, JAVA, CSHARP, VB, JS, GO, CPP, PYTHON, SQL, OBJECTIVEC, SWIFT, KOTLIN
        }

        @JsonProperty
        protected Language language;

        @JsonProperty
        protected String url;

        @JsonProperty
        protected Boolean useIncrementalScan;

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
    Policy.State policyState = Policy.State.NONE;

    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
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