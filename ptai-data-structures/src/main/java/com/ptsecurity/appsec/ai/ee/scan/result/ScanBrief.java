package com.ptsecurity.appsec.ai.ee.scan.result;

import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.*;

public class ScanBrief {
    @NonNull
    @Getter
    @Setter
    protected String ptaiServerVersion;

    @NonNull
    @Getter
    @Setter
    protected String ptaiAgentVersion;

    @NonNull
    @Getter
    @Setter
    protected UUID id;

    @NonNull
    @Getter
    @Setter
    protected UUID projectId;

    @NonNull
    @Getter
    @Setter
    protected String projectName;

    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    public static class ScanSettings {
        @NonNull
        protected UUID id;

        public static enum Engine {
            AI, PM, TAINT, DC, FINGERPRINT, CONFIGURATION, BLACKBOX
        }

        @Builder.Default
        protected final Set<Engine> engines = new HashSet<>();

        protected Boolean unpackUserPackages;

        protected Boolean downloadDependencies;

        protected Boolean usePublicAnalysisMethod;

        protected Boolean useEntryAnalysisPoint;

        public enum Language {
            PHP, JAVA, CSHARP, VB, JS, GO, CPP, PYTHON, SQL, OBJECTIVEC, SWIFT, KOTLIN
        }
        protected Language language;

        protected String url;

        protected Boolean useIncrementalScan;

        protected Boolean autocheckAfterScan;

        protected String customParameters;

        protected String javaParameters;
    }

    @NonNull
    @Getter
    @Setter
    protected ScanSettings scanSettings;

    @Getter
    @Setter
    @NonNull
    Policy.PolicyState policyState;

    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    public static class Statistic {
        /**
         * Scan execution date / time. Can't use Java 8 ZonedDateTime, Instant etc. as Jenkins
         * complaints "Refusing to marshal java.time.Instant for security reasons;
         * see https://jenkins.io/redirect/class-filter/"
         */
        @NonNull
        protected String scanDateIso8601;

        @NonNull
        protected String scanDurationIso8601;

        protected int totalFileCount;
        protected int totalUrlCount;
        protected int scannedFileCount;
        protected int scannedUrlCount;
    }

    @Getter
    @Setter
    protected Statistic statistic;

    public enum State {
        UNKNOWN, DONE, FAILED, ABORTED
    }

    @Getter
    @Setter
    @NonNull
    State state = State.UNKNOWN;
}