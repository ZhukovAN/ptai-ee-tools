package com.ptsecurity.appsec.ai.ee.scanresult;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.ptsecurity.appsec.ai.ee.BaseScanSettings;
import com.ptsecurity.appsec.ai.ee.scanresult.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.utils.json.Policy;
import lombok.*;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class ScanResult {
    @NonNull
    @Getter
    @Setter
    protected String ptaiApiVersion;

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
    protected BaseScanSettings scanSettings;

    @Getter
    @Setter
    @NonNull
    Policy.PolicyState policyState;

    @Getter
    protected final List<BaseIssue> issues = new ArrayList<>();

    @Getter
    @Setter
    @Builder
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